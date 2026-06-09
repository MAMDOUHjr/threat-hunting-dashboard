"""
gui/app.py
----------
ThreatHuntingApp — completely redesigned main window.

Layout:
  Left sidebar  — VM fleet list with status cards + global controls
  Right panel   — Tabbed report viewer (one tab per machine)
"""

import logging
import queue
import threading
from typing import Optional
import tkinter as tk

import customtkinter as ctk

from gui.report_panel import ReportPanel
from gui.vm_card import VMCard
from hunting.engine import ThreatHuntingEngine, load_vm_configs
from hunting.models import HuntReport, VMConfig, VMStatus

logger = logging.getLogger(__name__)


class ThreatHuntingApp(ctk.CTk):
    """
    Root application window — redesigned with a modern SOC-style aesthetic.
    """

    def __init__(self) -> None:
        super().__init__()

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.title("HUNTER x")
        self.geometry("1400x820")
        self.minsize(1000, 640)
        self.configure(fg_color="#060D1A")

        self._vms: list[VMConfig] = []
        self._cards: dict[str, VMCard] = {}
        self._report_queue: queue.Queue[HuntReport | str] = queue.Queue()
        self._hunt_count = 0

        self._build_layout()
        self._load_vms()
        self._poll_queue()

    # ------------------------------------------------------------------ #
    # Layout
    # ------------------------------------------------------------------ #

    def _build_layout(self) -> None:
        self.grid_columnconfigure(0, weight=0, minsize=260)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=0)
        self.grid_rowconfigure(1, weight=1)

        # ── Top header bar ────────────────────────────────────────────
        header = ctk.CTkFrame(self, fg_color="#060D1A", height=52)
        header.grid(row=0, column=0, columnspan=2, sticky="ew")
        header.grid_propagate(False)
        header.grid_columnconfigure(1, weight=1)

        # Logo / brand
        brand = ctk.CTkFrame(header, fg_color="transparent")
        brand.grid(row=0, column=0, padx=(16, 0), pady=10, sticky="w")

        ctk.CTkLabel(
            brand,
            text="◈ HUNTER",
            font=ctk.CTkFont(family="JetBrains Mono", size=16, weight="bold"),
            text_color="#38BDF8",
        ).grid(row=0, column=0)

        ctk.CTkLabel(
            brand,
            text=" x",
            font=ctk.CTkFont(family="JetBrains Mono", size=16, weight="bold"),
            text_color="#EF4444",
        ).grid(row=0, column=1)

        # Right: live clock + status indicator
        right_bar = ctk.CTkFrame(header, fg_color="transparent")
        right_bar.grid(row=0, column=1, padx=16, pady=10, sticky="e")

        self._clock_label = ctk.CTkLabel(
            right_bar,
            text="",
            font=ctk.CTkFont(family="JetBrains Mono", size=11),
            text_color="#334155",
        )
        self._clock_label.grid(row=0, column=1, padx=(8, 0))
        self._tick_clock()

        # Separator line
        ctk.CTkFrame(self, fg_color="#0F2040", height=1).grid(
            row=0, column=0, columnspan=2, sticky="ews", pady=(51, 0)
        )

        # ── Left sidebar ──────────────────────────────────────────────
        sidebar = ctk.CTkFrame(
            self,
            fg_color="#070E1C",
            corner_radius=0,
            border_width=0,
        )
        sidebar.grid(row=1, column=0, sticky="nsew", padx=0, pady=0)
        sidebar.grid_rowconfigure(2, weight=1)
        sidebar.grid_columnconfigure(0, weight=1)

        # Sidebar header
        sidebar_hdr = ctk.CTkFrame(sidebar, fg_color="transparent")
        sidebar_hdr.grid(row=0, column=0, sticky="ew", padx=12, pady=(14, 6))
        sidebar_hdr.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            sidebar_hdr,
            text="VM FLEET",
            font=ctk.CTkFont(family="JetBrains Mono", size=10, weight="bold"),
            text_color="#475569",
            anchor="w",
        ).grid(row=0, column=0, sticky="w")

        self._fleet_count = ctk.CTkLabel(
            sidebar_hdr,
            text="0 machines",
            font=ctk.CTkFont(family="JetBrains Mono", size=10),
            text_color="#334155",
            anchor="e",
        )
        self._fleet_count.grid(row=0, column=1, sticky="e")

        # Thin accent line under header
        ctk.CTkFrame(sidebar, fg_color="#0F2040", height=1).grid(
            row=1, column=0, sticky="ew", padx=10
        )

        # Scrollable VM cards
        self._vm_scroll = ctk.CTkScrollableFrame(
            sidebar,
            fg_color="#070E1C",
            scrollbar_button_color="#1E293B",
            scrollbar_button_hover_color="#334155",
        )
        self._vm_scroll.grid(row=2, column=0, sticky="nsew", padx=6, pady=6)
        self._vm_scroll.grid_columnconfigure(0, weight=1)

        # Bottom action buttons
        btn_area = ctk.CTkFrame(sidebar, fg_color="#060D1A", corner_radius=0)
        btn_area.grid(row=3, column=0, sticky="ew", padx=0, pady=0)
        btn_area.grid_columnconfigure((0, 1), weight=1)

        ctk.CTkFrame(btn_area, fg_color="#0F2040", height=1).grid(
            row=0, column=0, columnspan=2, sticky="ew"
        )

        ctk.CTkButton(
            btn_area,
            text="⚡ Test All",
            height=34,
            corner_radius=0,
            fg_color="#0A1525",
            hover_color="#111E35",
            text_color="#64748B",
            border_width=0,
            font=ctk.CTkFont(family="JetBrains Mono", size=11),
            command=self._on_test_all,
        ).grid(row=1, column=0, sticky="ew", padx=1, pady=(0, 0))

        ctk.CTkButton(
            btn_area,
            text="🎯 Hunt All",
            height=34,
            corner_radius=0,
            fg_color="#0A1F3A",
            hover_color="#0F2D55",
            text_color="#38BDF8",
            border_width=0,
            font=ctk.CTkFont(family="JetBrains Mono", size=11, weight="bold"),
            command=self._on_hunt_all,
        ).grid(row=1, column=1, sticky="ew", padx=1, pady=(0, 0))

        # ── Right: Report panel ───────────────────────────────────────
        self._report_panel = ReportPanel(self)
        self._report_panel.grid(row=1, column=1, sticky="nsew", padx=(1, 10), pady=(6, 10))

    # ------------------------------------------------------------------ #
    # Clock ticker
    # ------------------------------------------------------------------ #

    def _tick_clock(self) -> None:
        from datetime import datetime
        now = datetime.now().strftime("%Y-%m-%d  %H:%M:%S  UTC")
        self._clock_label.configure(text=now)
        self.after(1000, self._tick_clock)

    # ------------------------------------------------------------------ #
    # VM loading
    # ------------------------------------------------------------------ #

    def _load_vms(self) -> None:
        try:
            self._vms = load_vm_configs()
        except (FileNotFoundError, ValueError) as exc:
            self._report_panel.show_message(
                f"Could not load VM configuration:\n{exc}\n\n"
                "Please ensure config/vms.json exists and is valid.",
                is_error=True,
            )
            logger.error("Failed to load VM configs: %s", exc)
            return

        for i, vm in enumerate(self._vms):
            card = VMCard(
                parent=self._vm_scroll,
                vm=vm,
                on_hunt=self._on_hunt_vm,
            )
            card.grid(row=i, column=0, padx=4, pady=4, sticky="ew")
            self._cards[vm.name] = card

        self._fleet_count.configure(text=f"{len(self._vms)} machine{'s' if len(self._vms) != 1 else ''}")
        logger.info("Loaded %d VMs", len(self._vms))

    # ------------------------------------------------------------------ #
    # Hunt dispatching
    # ------------------------------------------------------------------ #

    def _on_hunt_vm(self, vm: VMConfig) -> None:
        card = self._cards.get(vm.name)
        if card:
            card.set_busy(True)
        self._report_panel.show_message(f"Hunting {vm.name} …  please wait.")
        threading.Thread(target=self._run_hunt, args=(vm,), daemon=True).start()

    def _on_hunt_all(self) -> None:
        for vm in self._vms:
            self._on_hunt_vm(vm)

    def _on_test_all(self) -> None:
        for card in self._cards.values():
            card._on_test_click()

    def _run_hunt(self, vm: VMConfig) -> None:
        engine = ThreatHuntingEngine(vm)
        report = engine.run()
        self._report_queue.put(report)
        logger.info("Hunt finished for %s, queued report", vm.name)

    # ------------------------------------------------------------------ #
    # Queue polling
    # ------------------------------------------------------------------ #

    def _poll_queue(self) -> None:
        try:
            while True:
                item = self._report_queue.get_nowait()
                if isinstance(item, HuntReport):
                    self._on_report_ready(item)
        except queue.Empty:
            pass
        self.after(200, self._poll_queue)

    def _on_report_ready(self, report: HuntReport) -> None:
        card = self._cards.get(report.vm.name)
        if card:
            status = VMStatus.ONLINE if not report.error else VMStatus.ERROR
            card.set_status(status)
            card.set_busy(False)
        self._report_panel.show_report(report)
        logger.info(
            "Report displayed — %s: %d finding(s)",
            report.vm.name,
            len(report.findings),
        )
