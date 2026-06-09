"""
gui/report_panel.py
-------------------
ReportPanel: Tabbed report viewer for multi-machine hunts.

Redesigned with:
  - Tab-based interface (one tab per VM report)
  - Dashboard-style summary section with severity metric cards
  - Rich text with color-coded findings
  - Compact export controls per tab
"""

import logging
import tkinter as tk
from pathlib import Path
from typing import Optional

import customtkinter as ctk

from hunting.models import HuntReport, Severity
from reports.exports import export_txt, export_json, format_report_text

logger = logging.getLogger(__name__)

SEV_COLORS: dict[str, str] = {
    "CRITICAL": "#F87171",
    "HIGH":     "#FB923C",
    "MEDIUM":   "#FCD34D",
    "LOW":      "#60A5FA",
    "SECTION":  "#94A3B8",
    "OK":       "#34D399",
    "WARN":     "#FCD34D",
    "HEADER":   "#38BDF8",
}

SEV_BG: dict[str, str] = {
    "CRITICAL": "#2C0A0A",
    "HIGH":     "#2C1306",
    "MEDIUM":   "#2C200A",
    "LOW":      "#0A1830",
}

SEV_BORDER: dict[str, str] = {
    "CRITICAL": "#EF4444",
    "HIGH":     "#F97316",
    "MEDIUM":   "#EAB308",
    "LOW":      "#3B82F6",
}


class _ReportTab(ctk.CTkFrame):
    """
    One tab's content: summary metrics + scrollable text report + export bar.
    """

    def __init__(self, parent, report: HuntReport) -> None:
        super().__init__(parent, fg_color="transparent")
        self._report = report
        self.grid_rowconfigure(2, weight=1)
        self.grid_columnconfigure(0, weight=1)
        self._build_summary()
        self._build_textbox()
        self._build_export_bar()

    # ------------------------------------------------------------------ #

    def _build_summary(self) -> None:
        """Severity metric cards row."""
        r = self._report

        summary_frame = ctk.CTkFrame(
            self,
            fg_color="#0F172A",
            corner_radius=8,
            border_width=1,
            border_color="#1E293B",
        )
        summary_frame.grid(row=0, column=0, padx=0, pady=(0, 8), sticky="ew")
        summary_frame.grid_columnconfigure((0, 1, 2, 3, 4), weight=1)

        # VM meta left
        meta = ctk.CTkFrame(summary_frame, fg_color="transparent")
        meta.grid(row=0, column=0, padx=12, pady=10, sticky="w")

        vm_name = ctk.CTkLabel(
            meta,
            text=r.vm.name,
            font=ctk.CTkFont(family="JetBrains Mono", size=14, weight="bold"),
            text_color="#F1F5F9",
            anchor="w",
        )
        vm_name.grid(row=0, column=0, sticky="w")

        ts = r.completed or r.started
        host_info = ctk.CTkLabel(
            meta,
            text=f"{r.vm.host}:{r.vm.port}  ·  {ts.strftime('%H:%M:%S')}",
            font=ctk.CTkFont(family="JetBrains Mono", size=10),
            text_color="#475569",
            anchor="w",
        )
        host_info.grid(row=1, column=0, sticky="w")

        # Duration badge
        dur_text = "N/A"
        if r.completed:
            delta = r.completed - r.started
            dur_text = f"{delta.total_seconds():.1f}s"

        dur_label = ctk.CTkLabel(
            meta,
            text=f"⏱ {dur_text}",
            font=ctk.CTkFont(family="JetBrains Mono", size=10),
            text_color="#64748B",
        )
        dur_label.grid(row=2, column=0, sticky="w", pady=(2, 0))

        # Error state short-circuit
        if r.error:
            err = ctk.CTkLabel(
                summary_frame,
                text=f"⚠  HUNT FAILED: {r.error}",
                font=ctk.CTkFont(family="JetBrains Mono", size=11, weight="bold"),
                text_color="#EF4444",
            )
            err.grid(row=0, column=1, columnspan=4, padx=12, pady=10)
            return

        # Severity metric cards
        sev_defs = [
            ("CRITICAL", Severity.CRITICAL, "#EF4444", "#2C0A0A", "#EF4444"),
            ("HIGH",     Severity.HIGH,     "#F97316", "#2C1306", "#F97316"),
            ("MEDIUM",   Severity.MEDIUM,   "#EAB308", "#2C200A", "#EAB308"),
            ("LOW",      Severity.LOW,       "#3B82F6", "#0A1830", "#3B82F6"),
        ]

        for col, (label, sev, color, bg, border) in enumerate(sev_defs, start=1):
            count = r.count_by_severity(sev)
            card = ctk.CTkFrame(
                summary_frame,
                corner_radius=6,
                fg_color=bg if count > 0 else "#0F172A",
                border_width=1,
                border_color=border if count > 0 else "#1E293B",
            )
            card.grid(row=0, column=col, padx=6, pady=10, sticky="ew")

            ctk.CTkLabel(
                card,
                text=str(count),
                font=ctk.CTkFont(family="JetBrains Mono", size=22, weight="bold"),
                text_color=color if count > 0 else "#334155",
            ).grid(row=0, column=0, padx=14, pady=(8, 0))

            ctk.CTkLabel(
                card,
                text=label,
                font=ctk.CTkFont(family="JetBrains Mono", size=9, weight="bold"),
                text_color=color if count > 0 else "#334155",
            ).grid(row=1, column=0, padx=14, pady=(0, 8))

        # Total findings badge (far right)
        total = len(r.findings)
        total_card = ctk.CTkFrame(
            summary_frame,
            corner_radius=6,
            fg_color="#0F172A" if total == 0 else "#0C1A2E",
            border_width=1,
            border_color="#334155" if total == 0 else "#38BDF8",
        )
        total_card.grid(row=0, column=5, padx=(6, 12), pady=10, sticky="ew")
        summary_frame.grid_columnconfigure(5, weight=1)

        ctk.CTkLabel(
            total_card,
            text=str(total),
            font=ctk.CTkFont(family="JetBrains Mono", size=22, weight="bold"),
            text_color="#38BDF8" if total > 0 else "#334155",
        ).grid(row=0, column=0, padx=14, pady=(8, 0))

        ctk.CTkLabel(
            total_card,
            text="TOTAL",
            font=ctk.CTkFont(family="JetBrains Mono", size=9, weight="bold"),
            text_color="#38BDF8" if total > 0 else "#334155",
        ).grid(row=1, column=0, padx=14, pady=(0, 8))

    # ------------------------------------------------------------------ #

    def _build_textbox(self) -> None:
        self._textbox = ctk.CTkTextbox(
            self,
            font=ctk.CTkFont(family="JetBrains Mono", size=11),
            fg_color="#060D1A",
            text_color="#CBD5E1",
            corner_radius=8,
            wrap="word",
            state="disabled",
            border_width=1,
            border_color="#1E293B",
        )
        self._textbox.grid(row=2, column=0, pady=(0, 6), sticky="nsew")
        self._configure_tags()
        self._populate()

    def _configure_tags(self) -> None:
        inner: tk.Text = self._textbox._textbox
        for tag_name, color in SEV_COLORS.items():
            inner.tag_configure(tag_name, foreground=color)

    def _populate(self) -> None:
        text = format_report_text(self._report)
        self._textbox.configure(state="normal")
        self._textbox.delete("1.0", "end")
        self._textbox.insert("end", text)
        self._apply_highlights(text)
        self._textbox.configure(state="disabled")

    def _apply_highlights(self, text: str) -> None:
        inner: tk.Text = self._textbox._textbox
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            start = "1.0"
            token = f"[{sev}]"
            while True:
                pos = inner.search(token, start, stopindex="end")
                if not pos:
                    break
                end_pos = f"{pos}+{len(token)}c"
                inner.tag_add(sev, pos, end_pos)
                start = end_pos
        start = "1.0"
        while True:
            pos = inner.search("=" * 10, start, stopindex="end", regexp=False)
            if not pos:
                break
            line_end = f"{pos} lineend"
            inner.tag_add("HEADER", pos, line_end)
            start = f"{pos}+1l"

    # ------------------------------------------------------------------ #

    def _build_export_bar(self) -> None:
        bar = ctk.CTkFrame(self, fg_color="transparent")
        bar.grid(row=3, column=0, pady=(0, 2), sticky="ew")
        bar.grid_columnconfigure(2, weight=1)

        ctk.CTkButton(
            bar,
            text="⬇ TXT",
            width=90,
            height=28,
            corner_radius=6,
            fg_color="#1E293B",
            hover_color="#273548",
            text_color="#94A3B8",
            border_width=1,
            border_color="#334155",
            font=ctk.CTkFont(family="JetBrains Mono", size=11),
            command=self._on_export_txt,
        ).grid(row=0, column=0, padx=(0, 4))

        ctk.CTkButton(
            bar,
            text="⬇ JSON",
            width=90,
            height=28,
            corner_radius=6,
            fg_color="#1E293B",
            hover_color="#273548",
            text_color="#94A3B8",
            border_width=1,
            border_color="#334155",
            font=ctk.CTkFont(family="JetBrains Mono", size=11),
            command=self._on_export_json,
        ).grid(row=0, column=1, padx=(0, 8))

        self._status_lbl = ctk.CTkLabel(
            bar,
            text="",
            font=ctk.CTkFont(family="JetBrains Mono", size=10),
            text_color="#475569",
            anchor="w",
        )
        self._status_lbl.grid(row=0, column=2, sticky="w")

    def _on_export_txt(self) -> None:
        try:
            path = export_txt(self._report)
            self._status_lbl.configure(text=f"Saved: {path.name}", text_color="#34D399")
        except Exception as exc:
            self._status_lbl.configure(text=f"Error: {exc}", text_color="#EF4444")

    def _on_export_json(self) -> None:
        try:
            path = export_json(self._report)
            self._status_lbl.configure(text=f"Saved: {path.name}", text_color="#34D399")
        except Exception as exc:
            self._status_lbl.configure(text=f"Error: {exc}", text_color="#EF4444")


# ============================================================== #


class ReportPanel(ctk.CTkFrame):
    """
    Tabbed report viewer: each VM hunt opens in its own tab.
    """

    def __init__(self, parent: ctk.CTk) -> None:
        super().__init__(
            parent,
            corner_radius=10,
            fg_color="#0A0F1E",
            border_width=1,
            border_color="#1E293B",
        )
        self._reports: dict[str, HuntReport] = {}
        self._tabs: dict[str, ctk.CTkFrame] = {}
        self._tab_btns: dict[str, ctk.CTkButton] = {}
        self._active_tab: Optional[str] = None
        self._build_ui()

    # ------------------------------------------------------------------ #

    def _build_ui(self) -> None:
        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # Tab bar header row
        self._tab_bar_outer = ctk.CTkFrame(
            self,
            fg_color="#060D1A",
            corner_radius=0,
            height=40,
            border_width=0,
        )
        self._tab_bar_outer.grid(row=0, column=0, sticky="ew", padx=0, pady=0)
        self._tab_bar_outer.grid_columnconfigure(0, weight=1)

        self._tab_scroll = ctk.CTkScrollableFrame(
            self._tab_bar_outer,
            fg_color="transparent",
            orientation="horizontal",
            height=40,
            scrollbar_button_color="#1E293B",
            scrollbar_button_hover_color="#334155",
        )
        self._tab_scroll.grid(row=0, column=0, sticky="ew", padx=6, pady=4)

        # Content area
        self._content = ctk.CTkFrame(self, fg_color="transparent")
        self._content.grid(row=1, column=0, sticky="nsew", padx=10, pady=(6, 10))
        self._content.grid_rowconfigure(0, weight=1)
        self._content.grid_columnconfigure(0, weight=1)

        # Placeholder when no reports
        self._placeholder = ctk.CTkFrame(
            self._content,
            fg_color="#0F172A",
            corner_radius=8,
            border_width=1,
            border_color="#1E293B",
        )
        self._placeholder.grid(row=0, column=0, sticky="nsew")
        self._placeholder.grid_rowconfigure(0, weight=1)
        self._placeholder.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            self._placeholder,
            text="◈",
            font=ctk.CTkFont(family="JetBrains Mono", size=36),
            text_color="#1E293B",
        ).grid(row=0, column=0)

        ctk.CTkLabel(
            self._placeholder,
            text="No reports yet.\nRun a hunt to see findings here.",
            font=ctk.CTkFont(family="JetBrains Mono", size=12),
            text_color="#334155",
            justify="center",
        ).grid(row=1, column=0, pady=(4, 0))

    # ------------------------------------------------------------------ #

    def show_report(self, report: HuntReport) -> None:
        """Display or refresh the report for this VM in its tab."""
        name = report.vm.name
        self._reports[name] = report

        # Destroy old tab content if re-hunting
        if name in self._tabs:
            self._tabs[name].destroy()

        # Hide placeholder
        self._placeholder.grid_remove()

        # Create new tab content
        tab_content = _ReportTab(self._content, report)
        tab_content.grid(row=0, column=0, sticky="nsew")
        self._tabs[name] = tab_content

        # Create tab button if needed
        if name not in self._tab_btns:
            self._add_tab_button(name, report)

        # Update tab button severity indicator
        self._update_tab_badge(name, report)

        # Switch to this tab
        self._switch_tab(name)

    def show_message(self, message: str, is_error: bool = False) -> None:
        """Show a status message in the placeholder area."""
        for child in self._placeholder.winfo_children():
            child.destroy()

        self._placeholder.grid()
        self._placeholder.grid_rowconfigure(0, weight=1)
        self._placeholder.grid_columnconfigure(0, weight=1)

        color = "#EF4444" if is_error else "#38BDF8"
        ctk.CTkLabel(
            self._placeholder,
            text=message,
            font=ctk.CTkFont(family="JetBrains Mono", size=12),
            text_color=color,
            justify="center",
            wraplength=500,
        ).grid(row=0, column=0, padx=20)

    # ------------------------------------------------------------------ #

    def _add_tab_button(self, name: str, report: HuntReport) -> None:
        btn = ctk.CTkButton(
            self._tab_scroll,
            text=f"  {name}  ",
            height=28,
            corner_radius=6,
            fg_color="#0F172A",
            hover_color="#1E293B",
            text_color="#64748B",
            border_width=1,
            border_color="#1E293B",
            font=ctk.CTkFont(family="JetBrains Mono", size=11),
            command=lambda n=name: self._switch_tab(n),
        )
        btn.pack(side="left", padx=(0, 4))
        self._tab_btns[name] = btn

    def _update_tab_badge(self, name: str, report: HuntReport) -> None:
        """Update tab button color based on highest severity."""
        btn = self._tab_btns.get(name)
        if not btn:
            return
        if report.error:
            btn.configure(text_color="#EF4444", border_color="#EF4444")
            return
        crit = report.count_by_severity(Severity.CRITICAL)
        high = report.count_by_severity(Severity.HIGH)
        med  = report.count_by_severity(Severity.MEDIUM)
        low  = report.count_by_severity(Severity.LOW)
        if crit:
            btn.configure(text_color="#F87171", border_color="#EF4444")
        elif high:
            btn.configure(text_color="#FB923C", border_color="#F97316")
        elif med:
            btn.configure(text_color="#FCD34D", border_color="#EAB308")
        elif low:
            btn.configure(text_color="#60A5FA", border_color="#3B82F6")
        else:
            btn.configure(text_color="#34D399", border_color="#10B981")

    def _switch_tab(self, name: str) -> None:
        """Make the selected tab visible, hide others."""
        # Deactivate all
        for n, tab in self._tabs.items():
            tab.grid_remove()
            if n in self._tab_btns:
                self._tab_btns[n].configure(
                    fg_color="#0F172A",
                    border_color="#1E293B",
                )

        # Activate selected
        if name in self._tabs:
            self._tabs[name].grid()
            self._active_tab = name
            if name in self._tab_btns:
                self._tab_btns[name].configure(
                    fg_color="#1E293B",
                    border_color="#38BDF8",
                )
