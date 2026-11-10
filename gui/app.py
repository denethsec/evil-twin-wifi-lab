"""Main application window (dashboard, network panel, detection lab, learn, logs)."""
from __future__ import annotations

import logging
import tkinter as tk
from tkinter import filedialog, ttk
from typing import Optional

import customtkinter as ctk

from core.events import EventBus
from core.models import Level, SimEvent
from core.simulation import (PHASE_INFO, ROGUE_BSSID, ScenarioConfig, SimState, SimulationEngine,
                             SimulationError)
from core.models import Security
from core.validators import ValidationError, validate_ssid
from . import theme as T
from .content import LESSONS
from .widgets import (InfoCard, LifecycleView, LogView, SignalChart, StatTile, StatusIndicator,
                      TopologyView)

log = logging.getLogger(__name__)

STATE_STYLE = {
    "IDLE": ("IDLE", T.MUTED),
    "RUNNING": ("RUNNING", T.GREEN),
    "COMPLETED": ("COMPLETED", T.BLUE),
    "STOPPED": ("STOPPED", T.AMBER),
}
ROGUE_SECURITY_CHOICES = {
    "Open (captive-portal style)": Security.OPEN,
    "WPA2-PSK (shared key known)": Security.WPA2,
}


class App(ctk.CTk):
    """Wires the GUI to a SimulationEngine through an EventBus (polled every ``poll_ms``)."""

    def __init__(self, engine: Optional[SimulationEngine] = None, poll_ms: int = 100) -> None:
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")
        super().__init__()
        self.title("Evil Twin Wi-Fi Lab - Educational Simulation (no real networks)")
        self.geometry("1280x820")
        self.minsize(1100, 720)
        self.configure(fg_color=T.BG)

        self.engine = engine or SimulationEngine(EventBus())
        self.bus = self.engine.bus
        self.poll_ms = poll_ms
        self._after_id: Optional[str] = None
        self._alerts = 0

        self._build_header()
        self.tabs = ctk.CTkTabview(self, fg_color=T.BG, segmented_button_selected_color="#1f6feb")
        self.tabs.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        for name in ("Dashboard", "Network Simulation", "Detection Lab", "Learn", "Event Log"):
            self.tabs.add(name)
        self._build_dashboard(self.tabs.tab("Dashboard"))
        self._build_network(self.tabs.tab("Network Simulation"))
        self._build_detection(self.tabs.tab("Detection Lab"))
        self._build_learn(self.tabs.tab("Learn"))
        self._build_logs(self.tabs.tab("Event Log"))

        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self._apply_state(self.engine.state.value)
        self._after_id = self.after(self.poll_ms, self._poll)

    # ------------------------------------------------------------------ build
    def _build_header(self) -> None:
        bar = ctk.CTkFrame(self, fg_color=T.PANEL, corner_radius=0, border_width=1, border_color=T.BORDER)
        bar.pack(fill="x")
        ctk.CTkLabel(bar, text="EVIL TWIN LAB", font=(T.FONT, 20, "bold"), text_color=T.GREEN).grid(
            row=0, column=0, padx=(14, 4), pady=(10, 0), sticky="w")
        ctk.CTkLabel(bar, text="Isolated educational simulation - virtual access points only",
                     font=(T.FONT, 11), text_color=T.MUTED).grid(row=1, column=0, padx=14, pady=(0, 10), sticky="w")

        controls = ctk.CTkFrame(bar, fg_color="transparent")
        controls.grid(row=0, column=1, rowspan=2, padx=10, pady=8, sticky="e")
        bar.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(controls, text="Lab SSID", text_color=T.MUTED).grid(row=0, column=0, padx=(0, 4))
        self.ssid_var = tk.StringVar(value="LabCorp-WiFi")
        self.ssid_entry = ctk.CTkEntry(controls, textvariable=self.ssid_var, width=150)
        self.ssid_entry.grid(row=0, column=1, padx=(0, 10))
        self.sec_menu = ctk.CTkOptionMenu(controls, values=list(ROGUE_SECURITY_CHOICES), width=210)
        self.sec_menu.grid(row=0, column=2, padx=(0, 10))
        self.speed_label = ctk.CTkLabel(controls, text="Step 1.2 s", text_color=T.MUTED, width=64)
        self.speed_label.grid(row=0, column=3)
        self.speed = ctk.CTkSlider(controls, from_=0.1, to=3.0, number_of_steps=29, width=110,
                                   command=self._on_speed)
        self.speed.set(1.2)
        self.speed.grid(row=0, column=4, padx=(0, 10))
        self.start_button = ctk.CTkButton(controls, text="▶ Start", width=84, fg_color="#238636",
                                          hover_color="#2ea043", command=self.on_start)
        self.start_button.grid(row=0, column=5, padx=3)
        self.stop_button = ctk.CTkButton(controls, text="■ Stop", width=84, fg_color="#da3633",
                                         hover_color="#f85149", command=self.on_stop)
        self.stop_button.grid(row=0, column=6, padx=3)
        self.reset_button = ctk.CTkButton(controls, text="↺ Reset", width=84, fg_color="#30363d",
                                          hover_color="#484f58", command=self.on_reset)
        self.reset_button.grid(row=0, column=7, padx=3)

        self.status = StatusIndicator(controls)
        self.status.grid(row=1, column=5, columnspan=3, pady=(2, 0))
        self.error_label = ctk.CTkLabel(controls, text="", text_color=T.RED, font=(T.FONT, 11))
        self.error_label.grid(row=1, column=0, columnspan=5, sticky="e", pady=(2, 0))

    def _build_dashboard(self, tab) -> None:
        tab.grid_columnconfigure((0, 1, 2, 3), weight=1)
        tab.grid_rowconfigure(3, weight=1)
        self.tile_state = StatTile(tab, "Simulation status")
        self.tile_aps = StatTile(tab, "Access points in range")
        self.tile_clients = StatTile(tab, "Clients on rogue AP")
        self.tile_alerts = StatTile(tab, "High/critical alerts")
        for i, tile in enumerate((self.tile_state, self.tile_aps, self.tile_clients, self.tile_alerts)):
            tile.grid(row=0, column=i, sticky="ew", padx=4, pady=4)
        ctk.CTkLabel(tab, text="Attack lifecycle (educational)", font=(T.FONT, 13, "bold"),
                     text_color=T.TEXT).grid(row=1, column=0, columnspan=4, sticky="w", padx=6, pady=(8, 0))
        self.lifecycle = LifecycleView(tab)
        self.lifecycle.grid(row=2, column=0, columnspan=4, sticky="ew", padx=4, pady=4)
        self.live_log = LogView(tab)
        self.live_log.grid(row=3, column=0, columnspan=4, sticky="nsew", padx=4, pady=4)

    def _build_network(self, tab) -> None:
        tab.grid_columnconfigure((0, 1), weight=1)
        tab.grid_rowconfigure(1, weight=1)
        self.legit_card = InfoCard(tab, "ORIGINAL (LEGITIMATE) ACCESS POINT", T.GREEN)
        self.legit_card.grid(row=0, column=0, sticky="nsew", padx=4, pady=4)
        self.rogue_card = InfoCard(tab, "SIMULATED ROGUE ACCESS POINT", T.RED)
        self.rogue_card.grid(row=0, column=1, sticky="nsew", padx=4, pady=4)
        self.topology = TopologyView(tab)
        self.topology.grid(row=1, column=0, columnspan=2, sticky="nsew", padx=4, pady=4)
        self.legit_card.update_ap(None)
        self.rogue_card.update_ap(None)

    def _build_detection(self, tab) -> None:
        tab.grid_columnconfigure(0, weight=3)
        tab.grid_columnconfigure(1, weight=2)
        tab.grid_rowconfigure(1, weight=1)
        tab.grid_rowconfigure(2, weight=1)
        top = ctk.CTkFrame(tab, fg_color="transparent")
        top.grid(row=0, column=0, columnspan=2, sticky="ew", padx=4, pady=4)
        self.scan_button = ctk.CTkButton(top, text="Run detection scan", command=self.on_scan)
        self.scan_button.pack(side="left")
        self.trust_switch = ctk.CTkSwitch(top, text="Use admin trusted profile")
        self.trust_switch.select()
        self.trust_switch.pack(side="left", padx=14)
        self.verdict_label = ctk.CTkLabel(top, text="No scan yet", font=(T.FONT, 13, "bold"), text_color=T.MUTED)
        self.verdict_label.pack(side="left", padx=10)
        self.risk_bar = ctk.CTkProgressBar(top, width=180)
        self.risk_bar.set(0)
        self.risk_bar.pack(side="right")

        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("Lab.Treeview", background=T.PANEL, fieldbackground=T.PANEL, foreground=T.TEXT,
                        rowheight=28, borderwidth=0)
        style.configure("Lab.Treeview.Heading", background="#21262d", foreground=T.TEXT, relief="flat")
        style.map("Lab.Treeview", background=[("selected", "#1f6feb")])
        cols = ("ssid", "bssid", "ch", "sec", "dbm", "score", "verdict")
        self.tree = ttk.Treeview(tab, columns=cols, show="headings", style="Lab.Treeview", height=4)
        for col, title, width in zip(cols, ("SSID", "BSSID", "Ch", "Security", "Signal", "Risk", "Verdict"),
                                     (130, 150, 40, 80, 80, 50, 110)):
            self.tree.heading(col, text=title)
            self.tree.column(col, width=width, anchor="w")
        self.tree.tag_configure("bad", foreground=T.RED)
        self.tree.tag_configure("warn", foreground=T.AMBER)
        self.tree.tag_configure("ok", foreground=T.GREEN)
        self.tree.grid(row=1, column=0, sticky="nsew", padx=4, pady=4)

        self.findings_box = ctk.CTkTextbox(tab, fg_color=T.BG, font=(T.MONO, 11), wrap="word")
        self.findings_box.grid(row=2, column=0, sticky="nsew", padx=4, pady=4)
        self.recs_box = ctk.CTkTextbox(tab, fg_color=T.BG, font=(T.MONO, 11), wrap="word")
        self.recs_box.grid(row=1, column=1, sticky="nsew", padx=4, pady=4)
        self.chart = SignalChart(tab)
        self.chart.grid(row=2, column=1, sticky="nsew", padx=4, pady=4)
        self._set_text(self.findings_box, "Findings will appear here after a detection scan.")
        self._set_text(self.recs_box, "Security recommendations will appear here after a detection scan.")

    def _build_learn(self, tab) -> None:
        box = ctk.CTkTextbox(tab, fg_color=T.PANEL, font=(T.FONT, 13), wrap="word")
        box.pack(fill="both", expand=True, padx=4, pady=4)
        self._set_text(box, LESSONS)

    def _build_logs(self, tab) -> None:
        bar = ctk.CTkFrame(tab, fg_color="transparent")
        bar.pack(fill="x", padx=4, pady=4)
        ctk.CTkLabel(bar, text="Filter", text_color=T.MUTED).pack(side="left")
        self.filter_menu = ctk.CTkOptionMenu(bar, values=["ALL"] + [lv.value for lv in Level], width=120,
                                             command=self._on_filter)
        self.filter_menu.pack(side="left", padx=8)
        ctk.CTkButton(bar, text="Clear view", width=90, fg_color="#30363d", command=self._on_clear_view).pack(side="left")
        self.export_button = ctk.CTkButton(bar, text="Export log…", width=110, command=self.on_export)
        self.export_button.pack(side="left", padx=8)
        self.export_label = ctk.CTkLabel(bar, text="", text_color=T.MUTED)
        self.export_label.pack(side="left", padx=8)
        self.full_log = LogView(tab)
        self.full_log.pack(fill="both", expand=True, padx=4, pady=4)

    # --------------------------------------------------------------- helpers
    @staticmethod
    def _set_text(box: ctk.CTkTextbox, text: str) -> None:
        box.configure(state="normal")
        box.delete("1.0", "end")
        box.insert("1.0", text)
        box.configure(state="disabled")

    def _show_error(self, message: str) -> None:
        self.error_label.configure(text=message)

    def _on_speed(self, value: float) -> None:
        delay = round(float(value), 1)
        self.speed_label.configure(text=f"Step {delay:.1f} s")
        self.engine.config.step_delay = delay  # takes effect on the next step

    # -------------------------------------------------------------- callbacks
    def on_start(self) -> None:
        """Validate inputs, configure the engine and start the simulation."""
        self._show_error("")
        try:
            ssid = validate_ssid(self.ssid_var.get())
            config = ScenarioConfig(ssid=ssid, rogue_security=ROGUE_SECURITY_CHOICES[self.sec_menu.get()],
                                    step_delay=round(float(self.speed.get()), 1))
            self.engine.configure(config)
            self.engine.start()
        except (ValidationError, SimulationError) as exc:
            self._show_error(str(exc))
        except Exception as exc:  # never crash the GUI from a button callback
            log.exception("Unexpected error while starting")
            self._show_error(f"Unexpected error: {exc}")

    def on_stop(self) -> None:
        if not self.engine.stop():
            self._show_error("Nothing is running.")

    def on_reset(self) -> None:
        self._show_error("")
        self.engine.reset()

    def on_scan(self) -> None:
        """Run the detector against the current virtual scan on demand."""
        self._show_error("")
        try:
            self.engine.run_detection(use_trusted=bool(self.trust_switch.get()))
        except SimulationError as exc:
            self._show_error(str(exc))
        except Exception as exc:
            log.exception("Detection failed")
            self._show_error(f"Detection failed: {exc}")

    def _on_filter(self, level: str) -> None:
        self.full_log.reload(self.bus.history(), level)

    def _on_clear_view(self) -> None:
        self.full_log.clear()

    def export_log(self, path: str) -> int:
        """Write the log history to ``path``. Returns the number of lines written."""
        events = self.bus.history()
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(ev.formatted() for ev in events) + ("\n" if events else ""))
        return len(events)

    def on_export(self) -> None:
        path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text", "*.txt")],
                                            initialfile="evil_twin_lab_log.txt")
        if not path:
            return
        try:
            count = self.export_log(path)
            self.export_label.configure(text=f"Saved {count} lines to {path}", text_color=T.GREEN)
        except OSError as exc:
            self.export_label.configure(text=f"Export failed: {exc}", text_color=T.RED)

    # -------------------------------------------------------------- event loop
    def _poll(self) -> None:
        try:
            for event in self.bus.drain():
                self._handle(event)
        except Exception:
            log.exception("Error while handling simulation events")
        self._after_id = self.after(self.poll_ms, self._poll)

    def _handle(self, ev: SimEvent) -> None:
        if ev.kind == "log":
            self.live_log.append(ev)
            self.full_log.append(ev)
        elif ev.kind == "state":
            self._apply_state(ev.data["state"])
        elif ev.kind == "phase":
            idx = ev.data["phase"]
            self.lifecycle.set_stage(idx, complete=idx >= len(PHASE_INFO))
        elif ev.kind in ("ap", "client"):
            self._refresh_world()
        elif ev.kind == "signal":
            self._refresh_chart()
        elif ev.kind == "detection":
            self._show_report(ev.data["report"])
        elif ev.kind == "reset":
            self._clear_views()

    def _apply_state(self, state: str) -> None:
        text, color = STATE_STYLE.get(state, (state, T.MUTED))
        running = state == SimState.RUNNING.value
        self.status.set(text, color)
        self.tile_state.set(text, color)
        self.start_button.configure(state="disabled" if running else "normal")
        self.stop_button.configure(state="normal" if running else "disabled")
        self.ssid_entry.configure(state="disabled" if running else "normal")
        self.sec_menu.configure(state="disabled" if running else "normal")

    def _refresh_world(self) -> None:
        snap = self.engine.snapshot()
        self.legit_card.update_ap(snap["legit"])
        self.rogue_card.update_ap(snap["rogue"])
        self.topology.update_world(snap["legit"], snap["rogue"], snap["clients"])
        self.tile_aps.set(str(sum(1 for k in ("legit", "rogue") if snap[k])))
        victims = sum(1 for c in snap["clients"] if c.connected_bssid == ROGUE_BSSID)
        self.tile_clients.set(f"{victims}/{len(snap['clients'])}" if snap["clients"] else "-",
                              T.RED if victims else T.TEXT)

    def _refresh_chart(self) -> None:
        snap = self.engine.snapshot()
        series = {}
        if snap["legit"]:
            series["Legitimate"] = (T.GREEN, snap["history"].get(snap["legit"].bssid, []))
        if snap["rogue"]:
            series["Rogue"] = (T.RED, snap["history"].get(snap["rogue"].bssid, []))
        self.chart.set_series(series)
        self._refresh_world()

    def _show_report(self, report) -> None:
        self.tree.delete(*self.tree.get_children())
        for a in report.assessments:
            tag = "bad" if a.score >= 60 else "warn" if a.score >= 25 else "ok"
            self.tree.insert("", "end", tags=(tag,), values=(
                a.ap.ssid, a.ap.bssid, a.ap.channel, a.ap.security.value, f"{a.ap.signal_dbm:.1f} dBm",
                a.score, a.verdict))
        lines = []
        for a in report.assessments:
            lines.append(f"{a.ap.bssid} - {a.verdict} (risk {a.score})")
            lines += [f"  [{f.severity.name}] {f.title}: {f.detail}" for f in a.findings] or ["  no findings"]
            lines.append("")
        self._set_text(self.findings_box, "\n".join(lines))
        self._set_text(self.recs_box, "SECURITY RECOMMENDATIONS\n\n" + "\n".join(
            f"{i}. {r}" for i, r in enumerate(report.recommendations, 1)))
        color = T.RED if report.overall_score >= 60 else T.AMBER if report.overall_score >= 25 else T.GREEN
        self.verdict_label.configure(text=report.verdict, text_color=color)
        self.risk_bar.configure(progress_color=color)
        self.risk_bar.set(report.overall_score / 100)
        self._alerts = report.alert_count
        self.tile_alerts.set(str(self._alerts), T.RED if self._alerts else T.GREEN)

    def _clear_views(self) -> None:
        self.live_log.clear()
        self.full_log.clear()
        self.lifecycle.set_stage(None)
        self.legit_card.update_ap(None)
        self.rogue_card.update_ap(None)
        self.topology.update_world(None, None, [])
        self.chart.set_series({})
        self.tree.delete(*self.tree.get_children())
        self._set_text(self.findings_box, "Findings will appear here after a detection scan.")
        self._set_text(self.recs_box, "Security recommendations will appear here after a detection scan.")
        self.verdict_label.configure(text="No scan yet", text_color=T.MUTED)
        self.risk_bar.set(0)
        self.tile_aps.set("0")
        self.tile_clients.set("-")
        self.tile_alerts.set("0")

    def _on_close(self) -> None:
        """Stop the worker thread and cancel the poll timer before closing."""
        try:
            self.engine.stop()
            if self._after_id:
                self.after_cancel(self._after_id)
        finally:
            self.destroy()
