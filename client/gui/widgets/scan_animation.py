# scan_animation.py
"""
ScanAnimation - smooth circular pulse animation for the circular scan button.
Uses tkinter Canvas .after to update UI on main thread.
"""

import math
import time
import threading


class ScanAnimation:
    def __init__(self, canvas, circle_id):
        self.canvas = canvas
        self.circle_id = circle_id
        self._running = False
        self._thread = None

        coords = self.canvas.coords(self.circle_id)
        if coords and len(coords) >= 4:
            self.center_x = (coords[0] + coords[2]) / 2
            self.center_y = (coords[1] + coords[3]) / 2
            self.radius = (coords[2] - coords[0]) / 2
        else:
            self.center_x = 110
            self.center_y = 110
            self.radius = 100

        self.rotation = 0.0
        self.pulse_phase = 0.0
        # speeds
        self.rotation_speed = 0.12
        self.pulse_speed = 0.18
        self.pulse_min = 0.95
        self.pulse_max = 1.08

    def start(self):
        if self._running:
            return
        self._running = True
        # use a thread to update and call canvas.after for UI updates
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=0.5)
        # reset visual state on main thread
        try:
            self.canvas.after(0, self._reset_circle)
        except Exception:
            pass

    def _run(self):
        while self._running:
            try:
                self.rotation += self.rotation_speed
                if self.rotation >= 2 * math.pi:
                    self.rotation -= 2 * math.pi
                self.pulse_phase += self.pulse_speed
                if self.pulse_phase >= 2 * math.pi:
                    self.pulse_phase -= 2 * math.pi

                pulse_scale = self.pulse_min + (self.pulse_max - self.pulse_min) * ((math.sin(self.pulse_phase) + 1) / 2.0)
                # schedule UI update
                self.canvas.after(0, self._update_circle, pulse_scale, self.rotation)
                time.sleep(0.032)  # ~30 FPS
            except Exception as e:
                print("ScanAnimation error:", e)
                break

    def _update_circle(self, scale, rotation):
        try:
            new_r = self.radius * scale
            x1 = self.center_x - new_r
            y1 = self.center_y - new_r
            x2 = self.center_x + new_r
            y2 = self.center_y + new_r
            self.canvas.coords(self.circle_id, x1, y1, x2, y2)

            # color glow effect
            intensity = int(140 + 115 * abs(math.sin(rotation)))
            intensity = max(0, min(255, intensity))
            color = f"#{intensity:02x}{intensity:02x}ff"
            try:
                self.canvas.itemconfig(self.circle_id, fill=color)
            except Exception:
                pass
        except Exception:
            pass

    def _reset_circle(self):
        try:
            x1 = self.center_x - self.radius
            y1 = self.center_y - self.radius
            x2 = self.center_x + self.radius
            y2 = self.center_y + self.radius
            self.canvas.coords(self.circle_id, x1, y1, x2, y2)
            self.canvas.itemconfig(self.circle_id, fill="#047eaf")
        except Exception:
            pass
