"""
Skybrush Log Analysis window.

This file is part of ArduPilot Methodic Configurator. https://github.com/ArduPilot/MethodicConfigurator

SPDX-FileCopyrightText: 2026 Amilcar do Carmo Lucas <amilcar.lucas@iav.de>

SPDX-License-Identifier: GPL-3.0-or-later
"""

import ssl
import sys
import tkinter as tk
from collections.abc import Callable
from contextlib import redirect_stdout, suppress
from io import StringIO
from logging import debug as logging_debug
from logging import error as logging_error
from logging import info as logging_info
from pathlib import Path
from threading import Lock
from tkinter import Toplevel, messagebox, ttk
from typing import TYPE_CHECKING, Any, cast

from skybrush_log_analyzer.analysis import to_agent_view
from skybrush_log_analyzer.config import load_config
from skybrush_log_analyzer.errors import (
    AccountUnreachable,
    ApplicationErrorWithMessage,
    BadRequest,
    ConfigError,
    InvalidAPIKey,
    ResponseParsingFailed,
    ServerError,
    Unauthenticated,
)
from skybrush_log_analyzer.utils import calculate_file_hash

from ardupilot_methodic_configurator import _, __version__
from ardupilot_methodic_configurator.backend_internet import webbrowser_open_url
from ardupilot_methodic_configurator.formatting import format_elapsed_time
from ardupilot_methodic_configurator.frontend_tkinter_base_window import BaseWindow
from ardupilot_methodic_configurator.frontend_tkinter_file_browser_tasks import BackgroundTaskRunner
from ardupilot_methodic_configurator.frontend_tkinter_show import show_tooltip

if TYPE_CHECKING:
    from skybrush_log_analyzer.api_client import APIClient
    from skybrush_log_analyzer.auth_client import AuthClient
    from skybrush_log_analyzer.typing import SuggestionCategory

_ACCOUNT_URL = "https://account.skybrush.io"

#: Serializes truststore aliasing when two background tasks start concurrently.
_TRUSTSTORE_ALIAS_LOCK = Lock()

#: Display color for each test-case status returned by the Skybrush API.
_STATUS_COLOR = {
    "FAIL": "red3",
    "WARN": "dark orange",
    "INFO": "#0055cc",
    "PASS": "dark green",
    "SKIP": "gray50",
    "NOT_APPLICABLE": "gray50",
}

#: Display order of test-case statuses, most severe first.
_STATUS_DISPLAY_ORDER = ("FAIL", "WARN", "INFO", "PASS", "SKIP", "NOT_APPLICABLE")

#: Prefix prepended to every console (logging) line emitted by the Skybrush log analysis integration.
_LOG_TAG = "[Skybrush log analysis]"


# ---------------- truststore handling ----------------


def _align_truststore_with_system_cert_injection() -> None:
    """
    Point the `truststore` module at the copy already injected into ssl, to avoid a second injection.

    The pip_system_certs dependency of this application uses a .pth hook to inject pip's vendored
    copy of truststore into the standard ssl module at interpreter startup. skybrush-log-analyzer
    depends on httpx2, which imports its own (standalone) truststore copy: those copies get
    stacked, the standalone constants capture the already-patched ssl.SSLContext, and every TLS
    request fails with "RecursionError: maximum recursion depth exceeded" on Python 3.13.
    Aliasing `truststore` to pip's vendored copy makes httpx2 land on the working injection.
    No-op when pip is not available (e.g. frozen applications) or when nothing was injected.
    """
    with _TRUSTSTORE_ALIAS_LOCK:
        try:
            from pip._vendor import truststore as vendored_truststore  # noqa: PLC0415
        except ImportError:
            return
        try:
            is_injected = isinstance(ssl.create_default_context(), vendored_truststore.SSLContext)
        except OSError:
            return
        if not is_injected:
            return
        prefix = "pip._vendor.truststore"
        for name, module in list(sys.modules.items()):
            if name == prefix or name.startswith(f"{prefix}."):
                alias = f"truststore{name[len(prefix) :]}"
                if sys.modules.get(alias) is not module:
                    sys.modules[alias] = module
                    logging_debug(
                        _("%s Aliasing module '%s' to '%s' to reuse the visible truststore copy"), _LOG_TAG, alias, name
                    )


# ---------------- Skybrush API clients ----------------


def _create_skybrush_clients() -> tuple["APIClient", "AuthClient"]:
    """Create Skybrush API and authentication clients from the local analyzer configuration."""
    _align_truststore_with_system_cert_injection()
    from skybrush_log_analyzer.api_client import APIClient  # noqa: PLC0415
    from skybrush_log_analyzer.auth_client import AuthClient  # noqa: PLC0415

    config = load_config()
    auth_client = AuthClient(config)
    return APIClient(config, auth_client), auth_client


# ---------------- Skybrush API error messages ----------------


_SKYBRUSH_ERROR_MESSAGES: tuple[tuple[type[Exception], str], ...] = (
    (
        Unauthenticated,
        _("Not logged in. Use the Log in button to configure the API key."),
    ),
    (InvalidAPIKey, _("The Skybrush API key is invalid or has been revoked. Create a new one at {account_url}.")),
    (AccountUnreachable, _("Could not reach the Skybrush Account server at {account_url}.")),
    (ConfigError, _("Invalid 'skybrush-log-analyzer' configuration: {message}")),
    (BadRequest, _("The Skybrush API rejected the request: {message}")),
    (ServerError, _("The Skybrush API is currently unavailable.")),
    (ResponseParsingFailed, _("The Skybrush API returned an unexpected response.")),
)


def _skybrush_error_message(error: Exception) -> str:
    """Translate a Skybrush API error into a localized, user-facing message."""
    for error_type, message_template in _SKYBRUSH_ERROR_MESSAGES:
        if isinstance(error, error_type):
            details = error.message if isinstance(error, ApplicationErrorWithMessage) else str(error)
            return message_template.format(message=details, account_url=_ACCOUNT_URL)
    return _("Skybrush API analysis failed: {error}").format(error=error)


# ---------------- display formatting helpers ----------------


def _format_api_version(version: dict[str, Any]) -> str:
    """Format the Skybrush API version info into one display line."""
    app_version = version.get("app_version") or "?"
    backend_core = version.get("paplan_version")
    if backend_core:
        return _("Skybrush API version: {version} (backend core: {paplan_version})").format(
            version=app_version, paplan_version=backend_core
        )
    return _("Skybrush API version: {version}").format(version=app_version)


def _version_tuple(version: object) -> tuple[int, ...] | None:
    """Parse a dotted version string into comparable integers; None when it is not parsable."""
    if not isinstance(version, str) or not version.strip():
        return None
    try:
        return tuple(int(part) for part in version.strip().split("."))
    except ValueError:
        return None


def _stored_analysis_is_stale(analysis: dict[str, Any], current_version: dict[str, Any]) -> tuple[bool, str, str]:
    """Whether stored results were produced by an older backend core than the Skybrush API currently runs."""
    stored_core = str(analysis.get("paplan_version") or "")
    current_core = str(current_version.get("paplan_version") or "")
    stored_tuple = _version_tuple(stored_core)
    current_tuple = _version_tuple(current_core)
    is_stale = bool(stored_tuple and current_tuple and stored_tuple < current_tuple)
    return is_stale, stored_core, current_core


def _ordered_statuses(counts: dict[str, int]) -> list[str]:
    """Order test-case statuses by severity, then any unrecognized statuses alphabetically."""
    statuses = [status for status in _STATUS_DISPLAY_ORDER if status in counts]
    return statuses + sorted(status for status in counts if status not in _STATUS_DISPLAY_ORDER)


def _restore_pass_answers(view: dict[str, Any], analysis: dict[str, Any]) -> dict[str, Any]:
    """Re-attach the answer/value messages of PASS test results, omitted by the analyzer's agent view."""
    answers: dict[str, list[dict[str, Any]]] = {}
    for result in analysis.get("test_results") or []:
        name = result.get("test_name")
        messages = result.get("messages") or []
        if not isinstance(name, str) or not messages or name in answers:
            continue
        answers[name] = [
            {key: value for key, value in message.items() if key != "id" and value is not None}
            for message in messages
            if isinstance(message, dict)
        ]
    for result in view.get("test_results") or []:
        if result.get("status") == "PASS" and not result.get("messages"):
            messages = answers.get(result.get("test_name"))
            if messages:
                result["messages"] = messages
    return view


def _format_test_message(message: dict[str, Any]) -> tuple[str, str]:
    """Render a test-case message into a plain part plus a bold trailing value-with-unit part."""
    text = message.get("text") or message.get("message")
    if not isinstance(text, str) or not text.strip():
        # Fallback for unexpected message shapes returned by the Skybrush API.
        rendered = "; ".join(f"{key}: {value}" for key, value in message.items() if isinstance(value, str))
        return (rendered or str(message)), ""
    timestamp = message.get("timestamp")
    if isinstance(timestamp, (int, float)) and not isinstance(timestamp, bool):
        text = f"[{format_elapsed_time(timestamp)}] {text}"
    elif isinstance(timestamp, str) and timestamp.strip():
        text = f"[{timestamp.strip()}] {text}"
    value = message.get("value")
    if value is None or str(value) == "":
        return text, ""
    bold = f" {value}"
    unit = message.get("unit")
    if isinstance(unit, str) and unit.strip():
        bold += f" {unit}"
    return f"{text}:", bold


# ---------------- feedback dialog ----------------


class FeedbackDialog:
    """Modal dialog that collects user feedback and submits it to the Skybrush team (analyzer 'suggest')."""

    #: Categories accepted by the Skybrush suggestion endpoint, most relevant for analysis results first.
    CATEGORIES = ("bug", "test_case", "improvement", "feature", "other")

    def __init__(
        self,
        parent: tk.Tk | Toplevel,
        submit: Callable[[str, str, str, Callable[[object | None, Exception | None], None]], bool],
    ) -> None:
        self._parent = parent
        self._submit = submit
        self._root = Toplevel(parent)
        self._root.title(_("Send feedback"))
        self._root.geometry(f"+{parent.winfo_rootx() + 80}+{parent.winfo_rooty() + 80}")

        instructions = _(
            "Technical, self-contained feedback helps the Skybrush team the most.\n"
            "Describe what you did, what you expected, and what actually happened.\n"
            "Reference affected test names, measured values and log messages where relevant.\n"
            "If you miss a check, describe the new test that should examine the log (category 'test_case').\n"
            "Never include secrets such as passwords, tokens or API keys.\n"
            "The flight log name and its hash, plus version info, are appended automatically."
        )
        body = ttk.Frame(self._root, padding=(16, 12, 16, 12))
        body.pack(fill=tk.BOTH, expand=True)

        header = ttk.Frame(body)
        header.pack(side=tk.TOP, fill=tk.X)
        ttk.Label(header, text=_("Send feedback"), font=("TkDefaultFont", 14, "bold")).pack(anchor=tk.W)
        ttk.Label(header, text=instructions, foreground="gray50").pack(anchor=tk.W, pady=(4, 10))

        ttk.Label(body, text=_("Category")).pack(anchor=tk.W)
        self._category: str = self.CATEGORIES[0]
        category_box = ttk.Combobox(body, values=self.CATEGORIES, state="readonly", width=20)
        category_box.set(self._category)
        category_box.pack(anchor=tk.W, fill=tk.X, pady=(0, 8))
        category_box.bind("<<ComboboxSelected>>", self._on_category_selected)

        ttk.Label(body, text=_("Title")).pack(anchor=tk.W)
        self._title_entry = ttk.Entry(body)
        self._title_entry.pack(anchor=tk.W, fill=tk.X, pady=(0, 8))

        ttk.Label(body, text=_("Description")).pack(anchor=tk.W)
        description_row = ttk.Frame(body)
        description_row.pack(anchor=tk.W, fill=tk.BOTH, expand=True, pady=(0, 4))
        self._description_text = tk.Text(description_row, wrap=tk.WORD, height=8)
        description_scrollbar = ttk.Scrollbar(description_row, orient=tk.VERTICAL, command=self._description_text.yview)
        self._description_text.configure(yscrollcommand=description_scrollbar.set)
        description_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self._description_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        actions = ttk.Frame(body)
        actions.pack(side=tk.BOTTOM, fill=tk.X)
        self._progress_label = ttk.Label(actions, text="")
        self._progress_label.pack(side=tk.LEFT)
        ttk.Button(actions, text=_("Cancel"), command=self._root.destroy).pack(side=tk.RIGHT)
        self._submit_button = ttk.Button(actions, text=_("Submit"), command=self._on_submit_click)
        self._submit_button.pack(side=tk.RIGHT, padx=(0, 8))
        self._title_entry.focus_set()

    def _on_category_selected(self, event: "tk.Event[ttk.Combobox]") -> None:
        self._category = str(event.widget.get())

    def show(self) -> None:
        """Show the dialog modally."""
        self._root.transient(self._parent)
        self._root.grab_set()
        self._root.focus_set()
        self._parent.wait_window(self._root)

    def _on_submit_click(self) -> None:
        """Validate the input and hand the suggestion over to the background submission runner."""
        title = self._title_entry.get().strip()
        description = self._description_text.get("1.0", tk.END).strip()
        if not 1 <= len(title) <= 100 or not description:
            message = (
                _("Please provide a title between 1 and 100 characters.")
                if not 1 <= len(title) <= 100
                else _("Please describe the issue in the description field.")
            )
            messagebox.showerror(_("Send feedback"), message, parent=self._root)
            return
        if not self._submit(self._category, title, description, self._on_submitted):
            return
        self._submit_button.configure(state="disabled")
        self._progress_label.configure(text=_("Sending feedback to the Skybrush team..."))

    def _on_submitted(self, result: object | None, error: Exception | None) -> None:
        if not self._root.winfo_exists():
            return
        self._submit_button.configure(state="normal")
        self._progress_label.configure(text="")
        if error is not None:
            messagebox.showerror(_("Send feedback"), _skybrush_error_message(error), parent=self._root)
            return
        suggestion_id = result.get("id") if isinstance(result, dict) else None
        detail = _("Thank you for your feedback! The Skybrush team will review your suggestion.")
        if isinstance(suggestion_id, int):
            detail = f"{detail} (#{suggestion_id})"
        messagebox.showinfo(_("Send feedback"), detail, parent=self._root)
        self._root.destroy()


# ---------------- login dialog ----------------


class LoginDialog:
    """Modal dialog that stores the Skybrush API key (analyzer 'login --api-key' equivalent)."""

    #: The account area where users can generate and revoke API keys.
    DEVELOPER_AREA_URL = "https://account.skybrush.io/developer"

    def __init__(
        self, parent: tk.Tk | Toplevel, login: Callable[[str, Callable[[object | None, Exception | None], None]], bool]
    ) -> None:
        self._parent = parent
        self._login = login
        self._root = Toplevel(parent)
        self._root.title(_("Log in"))
        self._root.geometry(f"+{parent.winfo_rootx() + 80}+{parent.winfo_rooty() + 80}")
        self._root.minsize(400, 0)

        instructions = _(
            "A Skybrush API key is required to analyze flight logs.\n"
            "Generate it in the Skybrush Account developer area, then paste it here."
        )
        body = ttk.Frame(self._root, padding=(16, 12, 16, 12))
        body.pack(fill=tk.BOTH, expand=True)

        header = ttk.Frame(body)
        header.pack(side=tk.TOP, fill=tk.X)
        ttk.Label(header, text=_("Log in"), font=("TkDefaultFont", 14, "bold")).pack(anchor=tk.W)
        ttk.Label(header, text=instructions, foreground="gray50").pack(anchor=tk.W, pady=(4, 10))

        developer_row = ttk.Frame(body)
        developer_row.pack(side=tk.TOP, fill=tk.X)
        ttk.Button(
            developer_row,
            text=_("Open Skybrush Account"),
            command=lambda: webbrowser_open_url(self.DEVELOPER_AREA_URL),
        ).pack(side=tk.LEFT)
        ttk.Label(developer_row, text=_("Create or manage your API keys there"), foreground="gray50").pack(
            side=tk.LEFT, padx=(8, 0)
        )

        ttk.Label(body, text=_("API key")).pack(anchor=tk.W, pady=(12, 0))
        self._key_entry = ttk.Entry(body, show="\u2022", width=50)
        self._key_entry.pack(anchor=tk.W, fill=tk.X, pady=(0, 8))

        actions = ttk.Frame(body)
        actions.pack(side=tk.BOTTOM, fill=tk.X)
        self._progress_label = ttk.Label(actions, text="")
        self._progress_label.pack(side=tk.LEFT)
        ttk.Button(actions, text=_("Cancel"), command=self._root.destroy).pack(side=tk.RIGHT)
        self._login_button = ttk.Button(actions, text=_("Log in"), command=self._on_login_click)
        self._login_button.pack(side=tk.RIGHT, padx=(0, 8))

    def show(self) -> None:
        """Show the dialog modally."""
        self._root.transient(self._parent)
        self._root.grab_set()
        self._root.focus_set()
        self._key_entry.focus_set()
        self._parent.wait_window(self._root)

    def _on_login_click(self) -> None:
        """Validate the input and start the background key validation and storing."""
        api_key = self._key_entry.get().strip()
        if not api_key:
            messagebox.showerror(_("Log in"), _("Please paste your API key."), parent=self._root)
            return
        if not self._login(api_key, self._on_login_done):
            return
        self._login_button.configure(state="disabled")
        self._progress_label.configure(text=_("Validating the API key and logging in..."))

    def _on_login_done(self, _result: object | None, error: Exception | None) -> None:
        if not self._root.winfo_exists():
            return
        self._login_button.configure(state="normal")
        self._progress_label.configure(text="")
        if error is not None:
            messagebox.showerror(_("Log in"), _skybrush_error_message(error), parent=self._root)
            return
        self._root.destroy()


class SkybrushLogAnalysisWindow(BaseWindow):
    """Main window of the Skybrush log analysis integration."""

    def __init__(self, root_tk: tk.Tk | tk.Toplevel, logfile: str) -> None:
        super().__init__(root_tk)
        self.logfile = logfile
        self._analysis_runner = BackgroundTaskRunner(self.root.after)
        self._web_login_runner = BackgroundTaskRunner(self.root.after)
        self._auth_runner = BackgroundTaskRunner(self.root.after)
        self._feedback_runner = BackgroundTaskRunner(self.root.after)
        self._login_runner = BackgroundTaskRunner(self.root.after)
        self._logged_in = load_config().api_key is not None
        self._analysis_reused = False
        self._version_info: dict[str, Any] = {}
        #: True while the header version/log-in state has never been fetched successfully.
        self._version_check_pending = True
        self._force_refresh = False
        self._analysis_is_stale = False
        self._stale_version_details: tuple[str, str] = ("", "")
        self._find_bar: ttk.Frame | None = None
        self._find_entry: ttk.Entry | None = None
        self._find_count_label: ttk.Label | None = None
        self._find_matches: list[tuple[str, str]] = []
        self._find_index = -1
        self._last_find_query: str | None = None
        self._find_bar_visible = False

        self.root.title(_("Skybrush Log Analysis"))
        self.root.geometry(self.calculate_scaled_geometry(1050, 800))
        self.center_window(self.root, root_tk)
        self.root.resizable(width=True, height=True)

        self._build_header()
        self._build_footer()
        self._build_results_area()
        self._start_header_status_checks()

    # ---------------- window layout ----------------

    def _build_header(self) -> None:
        header = ttk.Frame(self.main_frame)
        header.pack(side=tk.TOP, fill=tk.X, padx=20, pady=(16, 8))

        left_column = ttk.Frame(header)
        left_column.pack(side=tk.LEFT, anchor=tk.NW)

        ttk.Label(left_column, text=_("Skybrush Log Analysis"), font=("TkDefaultFont", 16, "bold")).pack(anchor=tk.W)
        ttk.Label(
            left_column,
            text=_("Selected log: {filename}").format(filename=Path(self.logfile).name),
            font=("TkDefaultFont", 13),
        ).pack(anchor=tk.W, pady=(8, 0))

        self._version_label = ttk.Label(
            left_column, text=_("Skybrush API version unknown"), font=("TkDefaultFont", 12), foreground="gray50"
        )
        self._version_label.pack(anchor=tk.W, pady=(4, 0))
        self._auth_status_label = ttk.Label(
            left_column,
            text=_("Checking log-in status..."),
            font=("TkDefaultFont", 12),
            foreground="gray50",
            # Keep the status line narrow: an unwrapped 'not logged in' error message would widen the
            # left column beyond the window width and the packer would then clip the button row.
            wraplength=450,
        )
        self._auth_status_label.pack(anchor=tk.W)

        actions = ttk.Frame(header)
        actions.pack(side=tk.RIGHT, fill=tk.Y, anchor=tk.NE)

        buttons_row = ttk.Frame(actions)
        buttons_row.pack(side=tk.TOP, anchor=tk.NE)

        self._login_button = ttk.Button(buttons_row, text=self._login_button_text(), command=self._on_login_logout_click)
        self._login_button.pack(side=tk.LEFT)
        self._login_tooltip = show_tooltip(self._login_button, self._login_button_tooltip_text())

        self._run_analysis_button = ttk.Button(buttons_row, text=_("Run analysis"), command=self._on_run_analysis_click)
        self._run_analysis_button.pack(side=tk.LEFT, padx=(8, 0))
        show_tooltip(
            self._run_analysis_button,
            _("Upload the selected log to the Skybrush API and display the results"),
        )

        self._open_web_button = ttk.Button(
            buttons_row, text=_("Open in Skybrush Log Analyzer"), command=self._on_open_in_browser_click
        )
        self._open_web_button.pack(side=tk.LEFT, padx=(8, 0))
        show_tooltip(
            self._open_web_button,
            _("Open the analysis of the selected log in the Skybrush Log Analyzer web application"),
        )

        self._feedback_button = ttk.Button(buttons_row, text=_("Send feedback"), command=self._on_send_feedback_click)
        self._feedback_button.pack(side=tk.LEFT, padx=(8, 0))
        show_tooltip(
            self._feedback_button,
            _("Report a suspicious analysis result or suggest an improvement directly to the Skybrush team"),
        )

        # Status/command feedback right-aligned in the header, bottom-aligned with the log-in status line.
        self.status_label = ttk.Label(actions, text="", anchor=tk.E, justify="right", wraplength=400)
        self.status_label.pack(side=tk.BOTTOM, anchor=tk.SE)
        # Wrap no wider than the button row above it.
        self.root.update_idletasks()
        self.status_label.configure(wraplength=max(buttons_row.winfo_reqwidth(), 200))

    def _build_footer(self) -> None:
        footer = ttk.Frame(self.main_frame)
        footer.pack(side=tk.BOTTOM, fill=tk.X, padx=20, pady=(0, 14))
        ttk.Button(footer, text=_("Close"), command=self.root.destroy).pack(side=tk.RIGHT)

    def _build_results_area(self) -> None:
        results_row = ttk.Frame(self.main_frame)
        results_row.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=20, pady=(0, 8))
        self._results_row = results_row

        self.results_text = tk.Text(
            results_row,
            wrap=tk.WORD,
            height=20,
            state=tk.DISABLED,
            font=("TkDefaultFont", 12),
            padx=10,
            pady=8,
        )
        scrollbar = ttk.Scrollbar(results_row, orient=tk.VERTICAL, command=self.results_text.yview)
        self.results_text.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.results_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        for status, color in _STATUS_COLOR.items():
            self.results_text.tag_configure(f"status_{status}", foreground=color)
        self.results_text.tag_configure("summary", font=("TkDefaultFont", 12, "bold"))
        self.results_text.tag_configure("heading", font=("TkDefaultFont", 14, "bold"))
        self.results_text.tag_configure("bold", font=("TkDefaultFont", 12, "bold"))
        self.results_text.tag_configure("muted", foreground="gray50")
        self.results_text.tag_configure("bullet", foreground="#666666")
        self.results_text.tag_configure("error", foreground="red3")
        self.results_text.tag_configure("search_all", background="#fff3a0")
        self.results_text.tag_configure("search_current", background="#ffb36b")

        self.root.bind("<Control-f>", self._show_find_bar)
        self.root.bind("<F3>", self._on_find_next_key)
        self.root.bind("<Shift-F3>", self._on_find_prev_key)
        self.root.bind("<Escape>", self._on_escape_key)

        self._replace_results_text()
        self._append_results_text(_("No analysis results yet - click 'Run analysis' to analyze the selected log.\n"), "muted")
        self._finish_results_text()

    # ---------------- results text helpers ----------------

    def _set_status(self, text: str) -> None:
        """Update the status line above the results text window."""
        self.status_label.configure(text=text)

    def _replace_results_text(self) -> None:
        self.results_text.configure(state=tk.NORMAL)
        self.results_text.delete("1.0", tk.END)

    def _append_results_text(self, text: str, tag: str | tuple[str, ...] | None = None) -> None:
        if tag is None:
            self.results_text.insert(tk.END, text)
        else:
            tags = (tag,) if isinstance(tag, str) else tag
            # tags given as one Tcl list argument - multiple varargs would be read as extra chars.
            self.results_text.insert(tk.END, text, " ".join(tags))

    def _finish_results_text(self) -> None:
        self.results_text.configure(state=tk.DISABLED)
        self.results_text.yview_moveto(0.0)
        if self._find_bar_visible:
            self._refresh_find_matches(jump=False)

    # ---------------- find bar (Ctrl-F) ----------------

    def _show_find_bar(self, _event: object | None = None) -> None:
        """Show the browser-like find bar above the results text and focus its field."""
        if self._find_bar is None:
            self._find_bar = ttk.Frame(self.main_frame)
            ttk.Label(self._find_bar, text=_("Find:")).pack(side=tk.LEFT)
            self._find_entry = ttk.Entry(self._find_bar)
            self._find_entry.pack(side=tk.LEFT, padx=(6, 8), fill=tk.X, expand=True)
            self._find_count_label = ttk.Label(self._find_bar, foreground="gray50")
            self._find_count_label.pack(side=tk.LEFT)
            self._find_entry.bind("<Return>", lambda _event: self._jump_to_match(1))
            self._find_entry.bind("<Shift-Return>", lambda _event: self._jump_to_match(-1))
            self._find_entry.bind("<Escape>", lambda _event: self._hide_find_bar())
            self._find_entry.bind("<KeyRelease>", self._on_find_query_changed)
            ttk.Button(self._find_bar, text="\u2715", width=3, command=self._hide_find_bar).pack(side=tk.RIGHT, padx=(6, 0))
            ttk.Button(self._find_bar, text="\u2193", width=3, command=lambda: self._jump_to_match(1)).pack(side=tk.RIGHT)
            ttk.Button(self._find_bar, text="\u2191", width=3, command=lambda: self._jump_to_match(-1)).pack(side=tk.RIGHT)
        self._find_bar.pack_configure(side=tk.TOP, fill=tk.X, before=self._results_row, padx=20, pady=(0, 8))
        self._find_bar_visible = True
        if self._find_entry is not None:
            self._find_entry.focus_set()
            self._find_entry.select_range(0, tk.END)
            self._refresh_find_matches(jump=self._find_entry.get() != "")

    def _hide_find_bar(self) -> None:
        """Remove the find bar and all of its highlights."""
        self._find_bar_visible = False
        self._find_index = -1
        self._find_matches = []
        self._clear_find_highlights()
        if self._find_bar is not None:
            self._find_bar.pack_forget()

    def _clear_find_highlights(self) -> None:
        self.results_text.tag_remove("search_all", "1.0", tk.END)
        self.results_text.tag_remove("search_current", "1.0", tk.END)
        self.results_text.tag_remove("sel", "1.0", tk.END)
        if self._find_count_label is not None:
            self._find_count_label.configure(text="")

    def _on_find_query_changed(self, _event: "tk.Event[tk.Entry]") -> None:
        """Re-run the search only when the query text actually changed (e.g. not on F3/arrow key releases)."""
        current = self._find_entry.get() if self._find_entry is not None else ""
        if current == self._last_find_query:
            return
        self._refresh_find_matches(jump=True)

    def _refresh_find_matches(self, jump: bool) -> None:
        """Locate and highlight all occurrences of the find-bar query."""
        self._clear_find_highlights()
        self._find_matches = []
        self._find_index = -1
        query = self._find_entry.get() if self._find_entry is not None else ""
        self._last_find_query = query
        if not query:
            return
        widget = self.results_text
        matches: list[tuple[str, str]] = []
        start = str(widget.search(query, "1.0", nocase=True, stopindex=tk.END))
        while start:
            end = f"{start}+{len(query)}c"
            matches.append((start, end))
            widget.tag_add("search_all", start, end)
            start = str(widget.search(query, end, nocase=True, stopindex=tk.END))
        self._find_matches = matches
        if not matches:
            if self._find_count_label is not None:
                self._find_count_label.configure(text=_("No matches"))
            return
        if jump:
            self._jump_to_match(1)

    def _jump_to_match(self, step: int) -> None:
        """Select, highlight and scroll to the next/previous match, wrapping around."""
        total = len(self._find_matches)
        if total == 0:
            return
        self._find_index = (self._find_index + step) % total
        start, end = self._find_matches[self._find_index]
        self.results_text.tag_remove("search_current", "1.0", tk.END)
        self.results_text.tag_add("search_current", start, end)
        self.results_text.tag_remove("sel", "1.0", tk.END)
        self.results_text.tag_add("sel", start, end)
        self.results_text.see(end)
        self.results_text.see(start)
        if self._find_count_label is not None:
            self._find_count_label.configure(text=f"{self._find_index + 1}/{total}")

    def _on_find_next_key(self, _event: object) -> None:
        if self._find_bar_visible:
            self._jump_to_match(1)

    def _on_find_prev_key(self, _event: object) -> None:
        if self._find_bar_visible:
            self._jump_to_match(-1)

    def _on_escape_key(self, _event: object) -> None:
        if self._find_bar_visible:
            self._hide_find_bar()

    # ---------------- analysis run ----------------

    def _on_run_analysis_click(self) -> None:
        """Fetch the stored analysis of the log, uploading and analyzing it freshly when none exists yet."""
        if self._analysis_runner.active:
            return

        logfile = Path(self.logfile)
        if not logfile.is_file():
            messagebox.showerror(
                _("Skybrush Log Analysis"),
                _("Log file not found: {path}").format(path=self.logfile),
                parent=self.root,
            )
            return

        self._run_analysis_button.configure(state="disabled")
        self._set_status(_("Fetching the existing analysis from the Skybrush account"))
        if not self._analysis_runner.start(self._fetch_or_upload_analysis, self._on_analysis_progress, self._on_analysis_done):
            self._update_action_buttons()
            self._set_status("")

    def _on_analysis_progress(self, text: str) -> None:
        """Show the background phase updates above the results window."""
        self._set_status(text)

    def _fetch_or_upload_analysis(self, report_progress: Callable[..., None]) -> dict[str, Any]:
        """Reuse the stored account analysis when present, uploading the log otherwise. Worker thread."""
        client, auth_client = _create_skybrush_clients()
        # Refresh the API token before any request to avoid token expiration mid-operation.
        auth_client.refresh_token()
        force_refresh = self._force_refresh
        self._force_refresh = False
        self._analysis_is_stale = False
        logfile = Path(self.logfile)
        analysis = None
        if not force_refresh:
            try:
                analysis = client.get_analysis(logfile)
            except BadRequest:
                # The by-hash lookup failing (404) means this log was never analyzed within the account.
                analysis = None
        if isinstance(analysis, dict) and analysis.get("test_results"):
            self._analysis_reused = True
            try:
                current_version = cast("dict[str, Any]", client.version())
            except Exception as exception:  # pylint: disable=broad-exception-caught
                logging_debug(_("%s Fetching the Skybrush API version failed: %s"), _LOG_TAG, exception)
                current_version = {}
            self._analysis_is_stale, stored_core, current_core = _stored_analysis_is_stale(analysis, current_version)
            self._stale_version_details = (stored_core, current_core)
            return _restore_pass_answers(cast("dict[str, Any]", to_agent_view(analysis)), analysis)
        report_progress(_("Uploading log and running analysis through the Skybrush API - this can take a while"))
        self._analysis_reused = False
        analysis = cast("Any", client.analyze(logfile))
        return _restore_pass_answers(cast("dict[str, Any]", to_agent_view(analysis)), analysis)

    def _on_analysis_done(self, result: object | None, error: Exception | None) -> None:
        self._update_action_buttons()
        if error is not None:
            logging_error(_("%s Skybrush API analysis failed: %s"), _LOG_TAG, error)
            self._show_analysis_error(_skybrush_error_message(error))
            return
        if not isinstance(result, dict):
            self._show_analysis_error(_("The Skybrush API returned unexpected data."))
            return
        self._display_analysis_results(result)
        self._set_status(_("Existing Skybrush log analysis reused") if self._analysis_reused else _("Analysis completed"))
        if self._analysis_reused and self._analysis_is_stale:
            self._offer_fresh_analysis()
        # Successful server communication: silently retry a header version check that failed earlier.
        self._retry_pending_version_check()

    def _offer_fresh_analysis(self) -> None:
        """Ask the user whether to re-run an analysis that an older backend core produced."""
        stored_core, current_core = self._stale_version_details
        if messagebox.askyesno(
            _("Skybrush Log Analysis"),
            _(
                "This log was analyzed with backend core {stored},"
                " but the Skybrush API now runs backend core {current}.\n\n"
                "Re-run the analysis with the current backend core?"
            ).format(stored=stored_core or "?", current=current_core or "?"),
            parent=self.root,
        ):
            self._force_refresh = True
            self._on_run_analysis_click()

    # ---------------- login / logout ----------------

    def _login_button_text(self) -> str:
        return _("Log out from Skybrush Account") if self._logged_in else _("Log in to Skybrush Account")

    def _login_button_tooltip_text(self) -> str:
        return (
            _("Log out of the Skybrush analysis service and remove the stored API key")
            if self._logged_in
            else _("Log in to the Skybrush analysis service with a Skybrush Account API key")
        )

    def _update_login_button(self) -> None:
        """Sync the header login/logout button label and the service buttons with the authentication state."""
        self._login_button.configure(text=self._login_button_text())
        self._login_tooltip.text = self._login_button_tooltip_text()
        self._update_action_buttons()

    def _update_action_buttons(self) -> None:
        """Enable the Skybrush service buttons only when logged in; in-flight buttons stay disabled."""
        state = "normal" if self._logged_in else "disabled"
        if not self._analysis_runner.active:
            self._run_analysis_button.configure(state=state)
        if not self._web_login_runner.active:
            self._open_web_button.configure(state=state)
        if not self._feedback_runner.active:
            self._feedback_button.configure(state=state)

    def _on_login_logout_click(self) -> None:
        """Open the login dialog or perform the logout (analyzer 'login'/'logout' equivalents)."""
        if self._logged_in:
            self._apply_logout()
            return
        LoginDialog(self.root, self._start_login).show()
        # Refresh the header state in case the authentication outcome changed the labels.
        self._update_login_button()

    def _start_login(self, api_key: str, on_done: Callable[[object | None, Exception | None], None]) -> bool:
        """Validate a candidate API key against the account, storing it only when accepted."""
        if self._login_runner.active:
            return False

        def on_login_done(result: object | None, error: Exception | None) -> None:
            if error is None:
                self._logged_in = True
                self._version_check_pending = False
                self._update_login_button()
                self._set_status(_("Logged in to the Skybrush Account"))
                self._start_header_status_checks()
            on_done(result, error)

        return self._login_runner.start(lambda _progress: self._validate_and_store_api_key(api_key), None, on_login_done)

    def _validate_and_store_api_key(self, api_key: str) -> dict[str, Any]:
        """Run the analyzer 'login --api-key' command in-process, validating and storing the key. Worker thread."""
        _align_truststore_with_system_cert_injection()  # before the CLI imports its own truststore copy
        from skybrush_log_analyzer.cli import login_cmd  # noqa: PLC0415

        try:
            # login_cmd() prints to stdout; capture it and re-emit with the tag prefix on the logging channel.
            with redirect_stdout(StringIO()) as captured:
                login_cmd(api_key=api_key, local=False)
            for line in captured.getvalue().splitlines():
                if line:
                    logging_info(_("%s API key validation message: %s"), _LOG_TAG, line)
        except BaseException as error:  # pylint: disable=broad-exception-caught
            # The CLI command reports failures as typer.Exit; the underlying cause is what is displayed.
            cause = getattr(error, "__cause__", None)
            if isinstance(cause, Exception):
                raise cause from None
            raise
        return {}

    def _apply_logout(self) -> None:
        """Run the analyzer 'logout' operation in-process, removing the stored API key and token."""
        _align_truststore_with_system_cert_injection()  # before the analyzer imports its own truststore copy
        from skybrush_log_analyzer.config import logout  # noqa: PLC0415
        from skybrush_log_analyzer.errors import ConfigError  # noqa: PLC0415

        # Do not use logout_cmd(): the CLI reads a config snapshot taken at its module import time,
        # which in this application predates the API key being stored (it is first imported when
        # logging in), so logout_cmd() wrongly believes the user is not logged in.
        config = load_config()
        if config.api_key is None:
            self._logged_in = False
            self._update_login_button()
            self._set_logged_out_header()
            return
        try:
            logout(config)
        except (OSError, ConfigError) as error:
            messagebox.showerror(_("Skybrush Log Analysis"), _skybrush_error_message(error), parent=self.root)
            return
        self._logged_in = False
        self._version_info = {}
        self._version_check_pending = False
        self._update_login_button()
        self._set_logged_out_header()
        self._set_status(_("Logged out"))

    # ---------------- browser links ----------------

    def _on_open_in_browser_click(self) -> None:
        """Open the analysis of the selected log in the Skybrush Log Analyzer in the default browser."""
        if self._web_login_runner.active:
            return

        self._open_web_button.configure(state="disabled")
        self._set_status(_("Requesting a log-in link for the Skybrush Log Analyzer web application"))
        if not self._web_login_runner.start(lambda _progress: self._fetch_web_login_url(), None, self._on_web_login_done):
            self._update_action_buttons()
            self._set_status("")

    def _fetch_web_login_url(self) -> str:
        """Acquire a single-sign-on URL for the Skybrush Log Analyzer, deep-linking to this log's analysis."""
        client, _auth_client = _create_skybrush_clients()
        try:
            intent = client.get_analysis_view_intent(Path(self.logfile))
        except BadRequest:
            # No stored analysis for this log within the account; open the generic analyzer view.
            intent = None
        return cast("str", client.get_web_login_url(intent=intent))

    def _on_web_login_done(self, result: object | None, error: Exception | None) -> None:
        self._update_action_buttons()
        if error is not None:
            logging_error(_("%s Could not acquire a Skybrush web log-in link: %s"), _LOG_TAG, error)
            self._set_status("")
            messagebox.showerror(_("Skybrush Log Analysis"), _skybrush_error_message(error), parent=self.root)
            return
        if not isinstance(result, str) or not result:
            self._set_status("")
            messagebox.showerror(
                _("Skybrush Log Analysis"),
                _("The Skybrush API returned an unexpected response."),
                parent=self.root,
            )
            return
        # Acquiring the login link proves the server was reached; retry a pending header version check.
        self._retry_pending_version_check()
        if webbrowser_open_url(result):
            self._set_status(_("Skybrush Log Analyzer opened in the default browser"))
        else:
            messagebox.showerror(
                _("Skybrush Log Analysis"),
                _("Could not open the default web browser."),
                parent=self.root,
            )

    # ---------------- header status checks ----------------

    def _start_header_status_checks(self) -> None:
        """Fill the header version/log-in labels; the network part runs as background tasks."""
        if load_config().api_key:
            self._version_label.configure(text=_("Fetching Skybrush API version..."))
            if not self._auth_runner.start(
                lambda _progress: self._fetch_version_and_auth_state(), None, self._on_version_auth_done
            ):
                self._set_auth_status("", "gray50")
        else:
            # Mirrors the not-logged-in state of the analyzer 'auth-status' command.
            self._logged_in = False
            self._update_login_button()
            self._set_logged_out_header()

    def _set_logged_out_header(self) -> None:
        """Show the header in the not-logged-in state (analyzer 'auth-status' equivalent)."""
        self._version_label.configure(text=_("Skybrush API version: requires logging in"))
        self._set_auth_status(_skybrush_error_message(Unauthenticated()), "red3")

    def _fetch_version_and_auth_state(self) -> dict[str, Any]:
        """Verify log-in and fetch the Skybrush API version. Executed in a worker thread."""
        client, auth_client = _create_skybrush_clients()
        # Refresh the token explicitly, mirroring the analyzer 'auth-status' command flow.
        auth_client.refresh_token()
        version = client.version()
        return version if isinstance(version, dict) else {"app_version": str(version)}

    def _retry_pending_version_check(self) -> None:
        """Retry the header version/log-in check after any successful server communication."""
        if self._version_check_pending and not self._auth_runner.active:
            self._start_header_status_checks()

    def _on_version_auth_done(self, result: object | None, error: Exception | None) -> None:
        if error is not None:
            logging_error(_("%s Skybrush log-in or API version check failed: %s"), _LOG_TAG, error)
            if isinstance(error, (Unauthenticated, InvalidAPIKey, ConfigError)):
                # Definitively logged out: flip the header button to the Login state.
                self._logged_in = False
                self._update_login_button()
            self._version_label.configure(text=_("Skybrush API version unknown"), foreground="gray50")
            self._set_auth_status(_skybrush_error_message(error), "red3")
            return
        if not isinstance(result, dict):
            self._version_label.configure(text=_("Skybrush API version unknown"), foreground="gray50")
            self._set_auth_status(_("The Skybrush API returned an unexpected response."), "red3")
            return

        self._version_info = result
        self._version_check_pending = False
        if not self._logged_in:
            self._logged_in = True
            self._update_login_button()
        self._version_label.configure(text=_format_api_version(result), foreground="")
        self._set_auth_status(_("Authenticated at {account_url}").format(account_url=load_config().account_url), "dark green")

    def _set_auth_status(self, text: str, color: str) -> None:
        """Set the header log-in status line with its severity color."""
        self._auth_status_label.configure(text=text, foreground=color)

    # ---------------- feedback (analyzer 'suggest' equivalent) ----------------

    def _on_send_feedback_click(self) -> None:
        """Open the feedback dialog (analyzer 'suggest' command equivalent)."""

        def submit(
            category: str, title: str, description: str, on_done: Callable[[object | None, Exception | None], None]
        ) -> bool:
            return self._start_suggestion(category, title, description, on_done)

        FeedbackDialog(self.root, submit).show()

    def _start_suggestion(
        self, category: str, title: str, description: str, on_done: Callable[[object | None, Exception | None], None]
    ) -> bool:
        """Submit the suggestion through the Skybrush API in the background."""

        def on_suggestion_done(result: object | None, error: Exception | None) -> None:
            # A submitted suggestion proves the server was reached; use it to retry a pending version check.
            if error is None:
                self._retry_pending_version_check()
            on_done(result, error)

        if self._feedback_runner.active:
            return False
        return self._feedback_runner.start(
            lambda _progress: self._submit_suggestion(category, title, description), None, on_suggestion_done
        )

    def _submit_suggestion(self, category: str, title: str, description: str) -> dict[str, Any]:
        """Build a self-contained suggestion context and send it. Worker thread."""
        content_lines = [description, "", "---"]
        content_lines.append(_("ArduPilot Methodic Configurator {version}").format(version=__version__))
        logfile = Path(self.logfile)
        if logfile.is_file():
            content_lines.append(_("Flight log: {filename}").format(filename=logfile.name))
            with suppress(OSError):
                content_lines.append(_("Log file SHA-256: {hash}").format(hash=calculate_file_hash(logfile.read_bytes())))
        if self._version_info:
            content_lines.append(_format_api_version(self._version_info))
        client, _auth_client = _create_skybrush_clients()
        result = client.suggest(category=cast("SuggestionCategory", category), title=title, content="\n".join(content_lines))
        return cast("dict[str, Any]", result)

    # ---------------- results rendering ----------------

    def _show_analysis_error(self, message: str) -> None:
        self._set_status("")
        self._replace_results_text()
        self._append_results_text(message + "\n", "error")
        self._finish_results_text()
        messagebox.showerror(_("Skybrush Log Analysis"), message, parent=self.root)

    def _display_analysis_results(self, view: dict[str, Any]) -> None:
        """Render the compact analysis view into the results text window."""
        self._replace_results_text()

        note_title = view.get("note_title")
        if note_title:
            self._append_results_text(str(note_title) + "\n", "heading")
        note_description = view.get("note_description")
        if note_description:
            self._append_results_text(str(note_description) + "\n\n")

        counts: dict[str, int] = view.get("status_counts") or {}
        if counts:
            self._append_status_counts(counts)

        test_results = view.get("test_results") or []
        if not test_results:
            self._append_results_text(_("No test results were returned by the analysis.\n"), "muted")
        for result in test_results:
            self._append_result(result)

        note = view.get("note")
        if note:
            self._append_results_text("\n" + str(note) + "\n", "muted")

        self._finish_results_text()

    def _append_status_counts(self, counts: dict[str, int]) -> None:
        """Append the summary line, coloring each 'STATUS: n' segment with its status color."""
        self._append_results_text(_("Test cases: "), "summary")
        for index, status in enumerate(_ordered_statuses(counts)):
            if index:
                self._append_results_text(", ", "summary")
            self._append_results_text(f"{status}: {counts[status]}", ("summary", f"status_{status}"))
        self._append_results_text("\n\n", "summary")

    def _append_result(self, result: dict[str, Any]) -> None:
        status = str(result.get("status") or "UNKNOWN")
        name = str(result.get("test_name") or "").removeprefix("paplan.tests.").removeprefix("paplan.tests:")
        title = result.get("title")
        line = f"[{status}] {name}"
        if isinstance(title, str) and title:
            line += f" - {title}"
        color_tag = f"status_{status}" if status in _STATUS_COLOR else "muted"
        self._append_results_text(line + "\n", color_tag)
        for message in result.get("messages") or []:
            # Each answer line carries its own severity: color it like the status line would be.
            severity = str(message.get("severity") or "").upper()
            severity_tag = f"status_{severity}" if severity in _STATUS_COLOR else "bullet"
            plain, bold = _format_test_message(message)
            self._append_results_text(f"    \u2022 {plain}", severity_tag)
            if bold:
                self._append_results_text(bold, f"{severity_tag} bold")
            self._append_results_text("\n", severity_tag)
        self._append_results_text("\n")
