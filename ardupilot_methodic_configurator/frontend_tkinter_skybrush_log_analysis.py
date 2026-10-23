"""
Skybrush Log Analysis window.

This file is part of ArduPilot Methodic Configurator. https://github.com/ArduPilot/MethodicConfigurator

SPDX-FileCopyrightText: 2026 Amilcar do Carmo Lucas <amilcar.lucas@iav.de>

SPDX-License-Identifier: GPL-3.0-or-later
"""

import ssl
import sys
import tkinter as tk
from logging import debug as logging_debug
from logging import error as logging_error
from pathlib import Path
from threading import Lock
from tkinter import messagebox, ttk
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

from ardupilot_methodic_configurator import _
from ardupilot_methodic_configurator.backend_internet import webbrowser_open_url
from ardupilot_methodic_configurator.formatting import format_elapsed_time
from ardupilot_methodic_configurator.frontend_tkinter_base_window import BaseWindow
from ardupilot_methodic_configurator.frontend_tkinter_file_browser_tasks import BackgroundTaskRunner
from ardupilot_methodic_configurator.frontend_tkinter_show import show_tooltip

if TYPE_CHECKING:
    from skybrush_log_analyzer.api_client import APIClient
    from skybrush_log_analyzer.auth_client import AuthClient

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
                    logging_debug(_("Aliasing module '%s' to '%s' to reuse the visible truststore copy"), alias, name)


def _create_skybrush_clients() -> tuple["APIClient", "AuthClient"]:
    """Create Skybrush API and authentication clients from the local analyzer configuration."""
    _align_truststore_with_system_cert_injection()
    from skybrush_log_analyzer.api_client import APIClient  # noqa: PLC0415
    from skybrush_log_analyzer.auth_client import AuthClient  # noqa: PLC0415

    config = load_config()
    auth_client = AuthClient(config)
    return APIClient(config, auth_client), auth_client


_SKYBRUSH_ERROR_MESSAGES: tuple[tuple[type[Exception], str], ...] = (
    (
        Unauthenticated,
        _("Not logged in to the Skybrush Account. Run 'skybrush-log-analyzer login' to configure an API key."),
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


def _format_status_counts(counts: dict[str, int]) -> str:
    """Format test-case status counts in a stable, severity-first display order."""
    statuses = [status for status in _STATUS_DISPLAY_ORDER if status in counts]
    statuses += sorted(status for status in counts if status not in _STATUS_DISPLAY_ORDER)
    return ", ".join(f"{status}: {counts[status]}" for status in statuses)


def _format_test_message(message: dict[str, Any]) -> str:
    """Render a single test-case message, with a leading timestamp and a trailing value with unit."""
    text = message.get("text") or message.get("message")
    if not isinstance(text, str) or not text.strip():
        # Fallback for unexpected message shapes returned by the Skybrush API.
        rendered = "; ".join(f"{key}: {value}" for key, value in message.items() if isinstance(value, str))
        return rendered or str(message)
    timestamp = message.get("timestamp")
    if isinstance(timestamp, (int, float)) and not isinstance(timestamp, bool):
        text = f"[{format_elapsed_time(timestamp)}] {text}"
    elif isinstance(timestamp, str) and timestamp.strip():
        text = f"[{timestamp.strip()}] {text}"
    value = message.get("value")
    if value is None or str(value) == "":
        return text
    text = f"{text}: {value}"
    unit = message.get("unit")
    if isinstance(unit, str) and unit.strip():
        return f"{text} {unit}"
    return text


class SkybrushLogAnalysisWindow(BaseWindow):
    """Main window of the Skybrush log analysis integration."""

    def __init__(self, root_tk: tk.Tk | tk.Toplevel, logfile: str) -> None:
        super().__init__(root_tk)
        self.logfile = logfile
        self._analysis_runner = BackgroundTaskRunner(self.root.after)
        self._web_login_runner = BackgroundTaskRunner(self.root.after)
        self._auth_runner = BackgroundTaskRunner(self.root.after)

        self.root.title(_("Skybrush Log Analysis"))
        self.root.geometry(self.calculate_scaled_geometry(1050, 800))
        self.center_window(self.root, root_tk)
        self.root.resizable(width=True, height=True)

        self._build_header()
        self._build_footer()
        self._build_results_area()
        self._start_header_status_checks()

    def _build_header(self) -> None:
        header = ttk.Frame(self.main_frame)
        header.pack(side=tk.TOP, fill=tk.X, padx=20, pady=(16, 4))

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
            left_column, text=_("Checking log-in status..."), font=("TkDefaultFont", 12), foreground="gray50"
        )
        self._auth_status_label.pack(anchor=tk.W)

        actions = ttk.Frame(header)
        actions.pack(side=tk.RIGHT, anchor=tk.NE)

        self._run_analysis_button = ttk.Button(actions, text=_("Run analysis"), command=self._on_run_analysis_click)
        self._run_analysis_button.pack(side=tk.LEFT, padx=(8, 0))
        show_tooltip(
            self._run_analysis_button,
            _("Upload the selected log to the Skybrush API and display the results"),
        )

        self._open_web_button = ttk.Button(
            actions, text=_("Open in Skybrush Log Analyzer"), command=self._on_open_in_browser_click
        )
        self._open_web_button.pack(side=tk.LEFT, padx=(8, 0))
        show_tooltip(
            self._open_web_button,
            _("Open the Skybrush Log Analyzer in the default browser"),
        )

        self._open_account_button = ttk.Button(actions, text=_("Open Skybrush Account"), command=self._on_open_account_click)
        self._open_account_button.pack(side=tk.LEFT)
        show_tooltip(
            self._open_account_button,
            _("Open the Skybrush Account page for registration, login and API key management"),
        )

    def _build_footer(self) -> None:
        footer = ttk.Frame(self.main_frame)
        footer.pack(side=tk.BOTTOM, fill=tk.X, padx=20, pady=(0, 14))
        ttk.Button(footer, text=_("Close"), command=self.root.destroy).pack(side=tk.RIGHT)

    def _build_results_area(self) -> None:
        self.status_label = ttk.Label(self.main_frame, text="", font=("TkDefaultFont", 13))
        self.status_label.pack(side=tk.TOP, anchor=tk.W, padx=20, pady=(10, 6))

        results_row = ttk.Frame(self.main_frame)
        results_row.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=20, pady=(0, 8))

        self.results_text = tk.Text(
            results_row,
            wrap=tk.WORD,
            height=20,
            state=tk.DISABLED,
            font=("TkDefaultFont", 12),
        )
        scrollbar = ttk.Scrollbar(results_row, orient=tk.VERTICAL, command=self.results_text.yview)
        self.results_text.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.results_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        for status, color in _STATUS_COLOR.items():
            self.results_text.tag_configure(f"status_{status}", foreground=color)
        self.results_text.tag_configure("summary", font=("TkDefaultFont", 12, "bold"))
        self.results_text.tag_configure("heading", font=("TkDefaultFont", 14, "bold"))
        self.results_text.tag_configure("muted", foreground="gray50")
        self.results_text.tag_configure("bullet", foreground="#666666")
        self.results_text.tag_configure("error", foreground="red3")

        self._replace_results_text()
        self._append_results_text(_("No analysis results yet - click 'Run analysis' to analyze the selected log.\n"), "muted")
        self._finish_results_text()

    def _set_status(self, text: str) -> None:
        """Update the status line above the results text window."""
        self.status_label.configure(text=text)

    def _replace_results_text(self) -> None:
        self.results_text.configure(state=tk.NORMAL)
        self.results_text.delete("1.0", tk.END)

    def _append_results_text(self, text: str, tag: str | None = None) -> None:
        if tag is None:
            self.results_text.insert(tk.END, text)
        else:
            self.results_text.insert(tk.END, text, tag)

    def _finish_results_text(self) -> None:
        self.results_text.configure(state=tk.DISABLED)
        self.results_text.yview_moveto(0.0)

    def _on_run_analysis_click(self) -> None:
        """Upload the selected log to the Skybrush API and display the results."""
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
        self._set_status(_("Uploading log and running analysis through the Skybrush API - this can take a while"))
        if not self._analysis_runner.start(lambda _progress: self._analyze_log_background(), None, self._on_analysis_done):
            self._run_analysis_button.configure(state="normal")
            self._set_status("")

    def _analyze_log_background(self) -> dict[str, Any]:
        """Analyze the selected log through the Skybrush API. Executed in a worker thread."""
        client, auth_client = _create_skybrush_clients()
        # Refresh the API token before the upload to avoid token expiration mid-operation.
        auth_client.refresh_token()
        return cast("dict[str, Any]", to_agent_view(client.analyze(Path(self.logfile))))

    def _on_analysis_done(self, result: object | None, error: Exception | None) -> None:
        self._run_analysis_button.configure(state="normal")
        if error is not None:
            logging_error(_("Skybrush API analysis failed: %s"), error)
            self._show_analysis_error(_skybrush_error_message(error))
            return
        if not isinstance(result, dict):
            self._show_analysis_error(_("The Skybrush API returned unexpected data."))
            return
        self._display_analysis_results(result)
        self._set_status(_("Analysis completed"))

    def _on_open_in_browser_click(self) -> None:
        """Open the Skybrush Log Analyzer in the default browser."""
        if self._web_login_runner.active:
            return

        self._open_web_button.configure(state="disabled")
        self._set_status(_("Requesting a log-in link for the Skybrush Log Analyzer"))
        if not self._web_login_runner.start(lambda _progress: self._fetch_web_login_url(), None, self._on_web_login_done):
            self._open_web_button.configure(state="normal")
            self._set_status("")

    def _fetch_web_login_url(self) -> str:
        """Acquire a single-sign-on URL for the Skybrush Log Analyzer. Worker thread."""
        client, _auth_client = _create_skybrush_clients()
        return cast("str", client.get_web_login_url())

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
            self._version_label.configure(text=_("Skybrush API version: requires logging in"))
            self._set_auth_status(_skybrush_error_message(Unauthenticated()), "red3")

    def _fetch_version_and_auth_state(self) -> dict[str, Any]:
        """Verify log-in and fetch the Skybrush API version. Executed in a worker thread."""
        client, auth_client = _create_skybrush_clients()
        # Refresh the token explicitly, mirroring the analyzer 'auth-status' command flow.
        auth_client.refresh_token()
        version = client.version()
        return version if isinstance(version, dict) else {"app_version": str(version)}

    def _on_version_auth_done(self, result: object | None, error: Exception | None) -> None:
        if error is not None:
            logging_error(_("Skybrush log-in or API version check failed: %s"), error)
            self._version_label.configure(text=_("Skybrush API version unknown"), foreground="gray50")
            self._set_auth_status(_skybrush_error_message(error), "red3")
            return
        if not isinstance(result, dict):
            self._version_label.configure(text=_("Skybrush API version unknown"), foreground="gray50")
            self._set_auth_status(_("The Skybrush API returned an unexpected response."), "red3")
            return

        app_version = result.get("app_version")
        paplan_version = result.get("paplan_version")
        if paplan_version:
            version_text = _("Skybrush API version: {version} (backend core: {paplan_version})").format(
                version=app_version or "?", paplan_version=paplan_version
            )
        else:
            version_text = _("Skybrush API version: {version}").format(version=app_version or "?")
        self._version_label.configure(text=version_text, foreground="")
        self._set_auth_status(_("Authenticated at {account_url}").format(account_url=load_config().account_url), "dark green")

    def _set_auth_status(self, text: str, color: str) -> None:
        """Set the header log-in status line with its severity color."""
        self._auth_status_label.configure(text=text, foreground=color)

    def _on_open_account_click(self) -> None:
        """Open the Skybrush Account page in the default browser (analyzer 'account' command equivalent)."""
        url = load_config().account_url
        if webbrowser_open_url(url):
            self._set_status(_("Skybrush Account page opened in the default browser"))
        else:
            messagebox.showerror(
                _("Skybrush Log Analysis"),
                _("Could not open the default web browser."),
                parent=self.root,
            )

    def _on_web_login_done(self, result: object | None, error: Exception | None) -> None:
        self._open_web_button.configure(state="normal")
        if error is not None:
            logging_error(_("Could not acquire a Skybrush web log-in link: %s"), error)
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
        if webbrowser_open_url(result):
            self._set_status(_("Skybrush Log Analyzer opened in the default browser"))
        else:
            messagebox.showerror(
                _("Skybrush Log Analysis"),
                _("Could not open the default web browser."),
                parent=self.root,
            )

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
            self._append_results_text(
                _("Test cases: {counts}").format(counts=_format_status_counts(counts)) + "\n\n", "summary"
            )

        test_results = view.get("test_results") or []
        if not test_results:
            self._append_results_text(_("No test results were returned by the analysis.\n"), "muted")
        for result in test_results:
            self._append_result(result)

        note = view.get("note")
        if note:
            self._append_results_text("\n" + str(note) + "\n", "muted")

        self._finish_results_text()

    def _append_result(self, result: dict[str, Any]) -> None:
        status = str(result.get("status") or "UNKNOWN")
        name = str(result.get("test_name") or "")
        title = result.get("title")
        line = f"[{status}] {name}"
        if isinstance(title, str) and title:
            line += f" - {title}"
        self._append_results_text(line + "\n", f"status_{status}")
        for message in result.get("messages") or []:
            self._append_results_text(f"    \u2022 {_format_test_message(message)}\n", "bullet")
        self._append_results_text("\n")
