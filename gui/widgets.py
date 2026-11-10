"""Reusable widgets: status indicator, info cards, lifecycle, topology, chart, log view."""
from __future__ import annotations

import tkinter as tk
from typing import Dict, List, Optional, Sequence

import customtkinter as ctk

from core.models import AccessPoint, Client, SimEvent
from core.simulation import PHASE_INFO
from . import theme as T


class StatusIndicator(ctk.CTkFrame):
    """Coloured dot + text."""

    def __init__(self, master, text: str = "IDLE", color: str = T.MUTED, **kw):
        super().__init__(master, fg_color="transparent", **kw)
        self.dot = ctk.CTkLabel(self, text="●", text_color=color, font=(T.FONT, 18))
        self.dot.pack(side="left")
        self.label = ctk.CTkLabel(self, text=text, text_color=T.TEXT, font=(T.FONT, 13, "bold"))
        self.label.pack(side="left", padx=(4, 0))

    def set(self, text: str, color: str) -> None:
        self.dot.configure(text_color=color)
        self.label.configure(text=text)


class StatTile(ctk.CTkFrame):
    """Big number with a caption."""

    def __init__(self, master, caption: str, **kw):
        super().__init__(master, fg_color=T.PANEL, border_width=1, border_color=T.BORDER, corner_radius=8, **kw)
        self.value = ctk.CTkLabel(self, text="-", font=(T.FONT, 24, "bold"), text_color=T.TEXT)
        self.value.pack(padx=14, pady=(10, 0))
        ctk.CTkLabel(self, text=caption, font=(T.FONT, 11), text_color=T.MUTED).pack(padx=14, pady=(0, 10))

    def set(self, text: str, color: str = T.TEXT) -> None:
        self.value.configure(text=text, text_color=color)


class InfoCard(ctk.CTkFrame):
    """Key/value card describing one access point."""

    FIELDS = ("SSID", "BSSID", "Channel", "Security", "Signal", "Vendor")

    def __init__(self, master, title: str, accent: str, **kw):
        super().__init__(master, fg_color=T.PANEL, border_width=1, border_color=accent, corner_radius=8, **kw)
        ctk.CTkLabel(self, text=title, font=(T.FONT, 14, "bold"), text_color=accent).grid(
            row=0, column=0, columnspan=2, sticky="w", padx=12, pady=(10, 4))
        self.values: Dict[str, ctk.CTkLabel] = {}
        for i, name in enumerate(self.FIELDS, start=1):
            pad = (1, 12) if i == len(self.FIELDS) else 1
            ctk.CTkLabel(self, text=name, text_color=T.MUTED, font=(T.FONT, 12)).grid(
                row=i, column=0, sticky="w", padx=(12, 8), pady=pad)
            lbl = ctk.CTkLabel(self, text="-", text_color=T.TEXT, font=(T.MONO, 12), anchor="w")
            lbl.grid(row=i, column=1, sticky="w", padx=(0, 12), pady=pad)
            self.values[name] = lbl
        self.grid_columnconfigure(1, weight=1)

    def update_ap(self, ap: Optional[AccessPoint]) -> None:
        if ap is None:
            for lbl in self.values.values():
                lbl.configure(text="- not created -" if lbl is self.values["SSID"] else "-")
            return
        data = {"SSID": ap.ssid, "BSSID": ap.bssid, "Channel": str(ap.channel), "Security": ap.security.value,
                "Signal": f"{ap.signal_dbm:.1f} dBm", "Vendor": ap.vendor}
        for key, text in data.items():
            self.values[key].configure(text=text)


class LifecycleView(tk.Canvas):
    """Seven-stage attack lifecycle diagram; completed stages green, current stage amber."""

    def __init__(self, master, **kw):
        super().__init__(master, bg=T.PANEL, highlightthickness=0, height=120, **kw)
        self.current: Optional[int] = None
        self.done = -1
        self.bind("<Configure>", lambda _e: self.redraw())

    def set_stage(self, current: Optional[int], complete: bool = False) -> None:
        n = len(PHASE_INFO)
        self.current = None if (current is None or complete) else current
        self.done = n - 1 if complete else (-1 if current is None else current - 1)
        self.redraw()

    def redraw(self) -> None:
        self.delete("all")
        width = max(self.winfo_width(), 300)
        n = len(PHASE_INFO)
        gap = 18
        box_w = (width - 20 - gap * (n - 1)) / n
        for i, name in PHASE_INFO.items():
            idx = int(i)
            x0 = 10 + idx * (box_w + gap)
            if idx <= self.done:
                outline, fill, fg = T.GREEN, "#12261a", T.GREEN
            elif idx == self.current:
                outline, fill, fg = T.AMBER, "#2b2210", T.AMBER
            else:
                outline, fill, fg = T.BORDER, T.PANEL_ALT, T.MUTED
            self.create_rectangle(x0, 20, x0 + box_w, 100, outline=outline, fill=fill, width=2)
            self.create_text(x0 + box_w / 2, 36, text=str(idx + 1), fill=fg, font=(T.FONT, 13, "bold"))
            self.create_text(x0 + box_w / 2, 68, text=name, fill=fg, width=box_w - 8,
                             font=(T.FONT, 10), justify="center")
            if idx < n - 1:
                self.create_line(x0 + box_w + 2, 60, x0 + box_w + gap - 2, 60, fill=T.MUTED, arrow="last")


class TopologyView(tk.Canvas):
    """Virtual topology: legitimate AP (left), clients (middle), rogue AP (right)."""

    def __init__(self, master, **kw):
        super().__init__(master, bg=T.PANEL, highlightthickness=0, **kw)
        self._legit: Optional[AccessPoint] = None
        self._rogue: Optional[AccessPoint] = None
        self._clients: List[Client] = []
        self.bind("<Configure>", lambda _e: self.redraw())

    def update_world(self, legit, rogue, clients: Sequence[Client]) -> None:
        self._legit, self._rogue, self._clients = legit, rogue, list(clients)
        self.redraw()

    def _ap_box(self, x: float, y: float, ap: Optional[AccessPoint], title: str, color: str) -> None:
        self.create_rectangle(x - 95, y - 55, x + 95, y + 55, outline=color if ap else T.BORDER,
                              fill=T.PANEL_ALT, width=2, dash=() if ap else (4, 3))
        self.create_text(x, y - 38, text=title, fill=color if ap else T.MUTED, font=(T.FONT, 10, "bold"))
        text = f"{ap.ssid[:20]}\n{ap.bssid}\nch{ap.channel} {ap.security.value}" if ap else "not deployed"
        self.create_text(x, y + 8, text=text, fill=T.TEXT if ap else T.MUTED, font=(T.FONT, 9), justify="center")

    def redraw(self) -> None:
        self.delete("all")
        w, h = max(self.winfo_width(), 400), max(self.winfo_height(), 240)
        lx, rx, cx, cy = 110, w - 110, w / 2, h / 2
        n = max(len(self._clients), 1)
        ys = [h * (i + 1) / (n + 1) for i in range(len(self._clients))]
        for client, y in zip(self._clients, ys):
            target = None
            if self._legit and client.connected_bssid == self._legit.bssid:
                target, color = (lx + 95, cy), T.GREEN
            elif self._rogue and client.connected_bssid == self._rogue.bssid:
                target, color = (rx - 95, cy), T.RED
            if target:
                self.create_line(cx - 50, y, target[0], target[1], fill=color, width=2)
        self._ap_box(lx, cy, self._legit, "LEGITIMATE AP", T.GREEN)
        self._ap_box(rx, cy, self._rogue, "ROGUE AP (SIMULATED)", T.RED)
        for client, y in zip(self._clients, ys):
            on_rogue = bool(self._rogue and client.connected_bssid == self._rogue.bssid)
            color = T.RED if on_rogue else (T.GREEN if client.connected_bssid else T.MUTED)
            self.create_oval(cx - 56, y - 8, cx - 40, y + 8, fill=color, outline="")
            self.create_text(cx - 32, y, text=client.name, fill=T.TEXT, anchor="w", font=(T.FONT, 10))


class SignalChart(tk.Canvas):
    """Simple line chart of simulated RSSI history."""

    def __init__(self, master, **kw):
        super().__init__(master, bg=T.PANEL, highlightthickness=0, **kw)
        self._series: Dict[str, tuple] = {}
        self.bind("<Configure>", lambda _e: self.redraw())

    def set_series(self, series: Dict[str, tuple]) -> None:
        """series: label -> (colour, [dBm values])."""
        self._series = series
        self.redraw()

    def redraw(self) -> None:
        self.delete("all")
        w, h = max(self.winfo_width(), 300), max(self.winfo_height(), 150)
        left, right, top, bottom = 48, 12, 22, 22
        lo, hi = -95.0, -25.0

        def ypos(v: float) -> float:
            return top + (hi - v) / (hi - lo) * (h - top - bottom)

        for level in (-90, -70, -50, -30):
            y = ypos(level)
            self.create_line(left, y, w - right, y, fill=T.BORDER)
            self.create_text(left - 6, y, text=str(level), fill=T.MUTED, anchor="e", font=(T.FONT, 8))
        self.create_text(left, 8, text="Signal strength (dBm), simulated", fill=T.MUTED, anchor="w", font=(T.FONT, 9))
        longest = max((len(v) for _, v in self._series.values()), default=0)
        span = max(longest - 1, 1)
        lx = w - right - 4
        for label, (color, values) in self._series.items():
            # Series are right-aligned: an AP that appears later starts further right.
            offset = longest - len(values)
            pts = []
            for i, v in enumerate(values):
                pts += [left + (i + offset) / span * (w - left - right), ypos(v)]
            if len(pts) >= 4:
                self.create_line(*pts, fill=color, width=2)
            elif len(pts) == 2:
                self.create_oval(pts[0] - 3, pts[1] - 3, pts[0] + 3, pts[1] + 3, fill=color, outline="")
            self.create_text(lx, 8, text=label, fill=color, anchor="e", font=(T.FONT, 9, "bold"))
            lx -= 130


class LogView(ctk.CTkFrame):
    """Colour-coded, auto-scrolling read-only log with optional level filter."""

    def __init__(self, master, **kw):
        super().__init__(master, fg_color=T.PANEL, border_width=1, border_color=T.BORDER, corner_radius=8, **kw)
        self.box = ctk.CTkTextbox(self, fg_color=T.BG, text_color=T.TEXT, font=(T.MONO, 11), wrap="word")
        self.box.pack(fill="both", expand=True, padx=6, pady=6)
        for level, color in T.LEVEL_COLORS.items():
            self.box.tag_config(level, foreground=color)
        self.box.configure(state="disabled")
        self.filter_level = "ALL"

    def append(self, event: SimEvent) -> None:
        if self.filter_level != "ALL" and event.level.value != self.filter_level:
            return
        self.box.configure(state="normal")
        self.box.insert("end", event.formatted() + "\n", event.level.value)
        self.box.configure(state="disabled")
        self.box.see("end")

    def reload(self, events: Sequence[SimEvent], level: str = "ALL") -> None:
        self.filter_level = level
        self.clear()
        for ev in events:
            self.append(ev)

    def clear(self) -> None:
        self.box.configure(state="normal")
        self.box.delete("1.0", "end")
        self.box.configure(state="disabled")
