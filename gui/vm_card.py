"""
gui/vm_card.py
--------------
VMCard: A sleek, modern card widget for a single monitored VM.

Redesigned with:
  - Glassy dark panel aesthetic with accent glow
  - Compact status badge + animated indicator
  - Action buttons with hover effects
  - Pulse animation during busy state
"""

import threading
import logging
from typing import Callable

import customtkinter as ctk
import tkinter as tk

from hunting.models import VMConfig, VMStatus

logger = logging.getLogger(__name__)

# ── Colour palette ─────────────────────────────────────────────────────────
STATUS_COLORS: dict[VMStatus, str] = {
    VMStatus.UNKNOWN:  "#64748B",
    VMStatus.ONLINE:   "#10B981",
    VMStatus.OFFLINE:  "#EF4444",
    VMStatus.ERROR:    "#F59E0B",
}

STATUS_BG: dict[VMStatus, str] = {
    VMStatus.UNKNOWN:  "#1E293B",
    VMStatus.ONLINE:   "#022C22",
    VMStatus.OFFLINE:  "#2C0A0A",
    VMStatus.ERROR:    "#2C1A06",
}

STATUS_BORDER: dict[VMStatus, str] = {
    VMStatus.UNKNOWN:  "#334155",
    VMStatus.ONLINE:   "#059669",
    VMStatus.OFFLINE:  "#DC2626",
    VMStatus.ERROR:    "#D97706",
}


class VMCard(ctk.CTkFrame):
    """
    A card widget for a single VM — redesigned with SOC-style aesthetics.
    """

    def __init__(
        self,
        parent: ctk.CTkFrame,
        vm: VMConfig,
        on_hunt: Callable[[VMConfig], None],
        on_status_cb: Callable[[str, VMStatus], None] | None = None,
    ) -> None:
        super().__init__(
            parent,
            corner_radius=8,
            fg_color="#0F172A",
            border_width=1,
            border_color="#1E293B",
        )
        self.vm = vm
        self._on_hunt = on_hunt
        self._on_status_cb = on_status_cb
        self._status = VMStatus.UNKNOWN
        self._pulse_colors = ["#10B981", "#059669", "#047857", "#059669", "#10B981"]
        self._pulse_idx = 0
        self._pulsing = False
        self._build_ui()

    # ------------------------------------------------------------------ #

    def _build_ui(self) -> None:
        self.grid_columnconfigure(0, weight=1)

        # Top row: name + status badge
        top = ctk.CTkFrame(self, fg_color="transparent")
        top.grid(row=0, column=0, padx=10, pady=(10, 0), sticky="ew")
        top.grid_columnconfigure(0, weight=1)

        self._name_label = ctk.CTkLabel(
            top,
            text=self.vm.name,
            font=ctk.CTkFont(family="JetBrains Mono", size=13, weight="bold"),
            text_color="#F1F5F9",
            anchor="w",
        )
        self._name_label.grid(row=0, column=0, sticky="w")

        # Status badge (dot + text in a pill)
        self._badge_frame = ctk.CTkFrame(
            top,
            corner_radius=20,
            fg_color=STATUS_BG[VMStatus.UNKNOWN],
            border_width=1,
            border_color=STATUS_BORDER[VMStatus.UNKNOWN],
        )
        self._badge_frame.grid(row=0, column=1, sticky="e")

        self._status_dot = ctk.CTkLabel(
            self._badge_frame,
            text="●",
            font=ctk.CTkFont(size=8),
            text_color=STATUS_COLORS[VMStatus.UNKNOWN],
        )
        self._status_dot.grid(row=0, column=0, padx=(6, 2), pady=3)

        self._status_label = ctk.CTkLabel(
            self._badge_frame,
            text=VMStatus.UNKNOWN.value,
            font=ctk.CTkFont(family="JetBrains Mono", size=10, weight="bold"),
            text_color=STATUS_COLORS[VMStatus.UNKNOWN],
        )
        self._status_label.grid(row=0, column=1, padx=(0, 8), pady=3)

        # Host/port line
        self._host_label = ctk.CTkLabel(
            self,
            text=f"  {self.vm.host}:{self.vm.port}  ·  {self.vm.username}",
            font=ctk.CTkFont(family="JetBrains Mono", size=10),
            text_color="#475569",
            anchor="w",
        )
        self._host_label.grid(row=1, column=0, padx=4, pady=(2, 6), sticky="w")

        # Separator
        sep = ctk.CTkFrame(self, fg_color="#1E293B", height=1)
        sep.grid(row=2, column=0, sticky="ew", padx=10)

        # Buttons
        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.grid(row=3, column=0, padx=8, pady=(6, 10), sticky="ew")
        btn_frame.grid_columnconfigure((0, 1), weight=1)

        self._test_btn = ctk.CTkButton(
            btn_frame,
            text="⚡ Test",
            height=26,
            corner_radius=6,
            fg_color="#1E293B",
            hover_color="#273548",
            text_color="#94A3B8",
            border_width=1,
            border_color="#334155",
            font=ctk.CTkFont(family="JetBrains Mono", size=11),
            command=self._on_test_click,
        )
        self._test_btn.grid(row=0, column=0, padx=(0, 3), sticky="ew")

        self._hunt_btn = ctk.CTkButton(
            btn_frame,
            text="🎯 Hunt",
            height=26,
            corner_radius=6,
            fg_color="#0F3460",
            hover_color="#164080",
            text_color="#38BDF8",
            border_width=1,
            border_color="#1D4ED8",
            font=ctk.CTkFont(family="JetBrains Mono", size=11, weight="bold"),
            command=self._on_hunt_click,
        )
        self._hunt_btn.grid(row=0, column=1, padx=(3, 0), sticky="ew")

    # ------------------------------------------------------------------ #

    def set_status(self, status: VMStatus) -> None:
        """Update the status badge — called from GUI thread."""
        self._status = status
        color = STATUS_COLORS[status]
        bg = STATUS_BG[status]
        border = STATUS_BORDER[status]

        self._status_dot.configure(text_color=color)
        self._status_label.configure(text=status.value, text_color=color)
        self._badge_frame.configure(fg_color=bg, border_color=border)
        self.configure(border_color=border if status != VMStatus.UNKNOWN else "#1E293B")

        if self._on_status_cb:
            self._on_status_cb(self.vm.name, status)

    def set_busy(self, busy: bool) -> None:
        """Disable/enable buttons and run pulse animation when busy."""
        state = "disabled" if busy else "normal"
        self._test_btn.configure(state=state)
        self._hunt_btn.configure(state=state)
        self._pulsing = busy
        if busy:
            self._pulse_dot()

    def _pulse_dot(self) -> None:
        """Animate the status dot during a hunt."""
        if not self._pulsing:
            return
        colors = ["#38BDF8", "#0EA5E9", "#0284C7", "#0EA5E9", "#38BDF8"]
        self._status_dot.configure(text_color=colors[self._pulse_idx % len(colors)])
        self._pulse_idx += 1
        self.after(180, self._pulse_dot)

    # ------------------------------------------------------------------ #

    def _on_test_click(self) -> None:
        self.set_busy(True)
        self.set_status(VMStatus.UNKNOWN)
        threading.Thread(target=self._run_test, daemon=True).start()

    def _run_test(self) -> None:
        from hunting.engine import ThreatHuntingEngine
        engine = ThreatHuntingEngine(self.vm)
        success, detail = engine.test()
        status = VMStatus.ONLINE if success else VMStatus.OFFLINE
        self.after(0, lambda: self.set_status(status))
        self.after(0, lambda: self.set_busy(False))
        logger.info("Connection test %s for %s: %s", status.value, self.vm.name, detail)

    def _on_hunt_click(self) -> None:
        self._on_hunt(self.vm)
