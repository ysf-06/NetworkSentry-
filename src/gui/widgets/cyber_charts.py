"""Custom QPainter widgets replicating the Cyber Guardian & Traffic Overview UI designs."""

from __future__ import annotations

import math
from typing import List, Optional, Sequence, Tuple

from PySide6.QtCore import QPointF, QRectF, Qt, Signal
from PySide6.QtGui import (
    QColor,
    QFont,
    QIcon,
    QLinearGradient,
    QPainter,
    QPainterPath,
    QPen,
    QPixmap,
    QPolygonF,
    QRadialGradient,
)
from PySide6.QtWidgets import QSlider, QWidget

from src.core.traffic_monitor import TCP_FLAG_SERIES, TrafficSample


def create_cyber_guardian_icon(size: int = 64) -> QIcon:
    """Render the golden Cyber Guardian shield emblem into a QIcon."""
    pix = render_shield_pixmap(size)
    return QIcon(pix)


def render_shield_pixmap(size: int = 64) -> QPixmap:
    """Render the metallic gold & dark obsidian Cyber Guardian shield pixmap."""
    pix = QPixmap(size, size)
    pix.fill(Qt.GlobalColor.transparent)

    painter = QPainter(pix)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)

    s = float(size)
    path = QPainterPath()
    path.moveTo(s * 0.50, s * 0.08)
    path.lineTo(s * 0.86, s * 0.22)
    path.cubicTo(s * 0.86, s * 0.55, s * 0.72, s * 0.78, s * 0.50, s * 0.92)
    path.cubicTo(s * 0.28, s * 0.78, s * 0.14, s * 0.55, s * 0.14, s * 0.22)
    path.closeSubpath()

    bg_grad = QLinearGradient(0, s * 0.08, 0, s * 0.92)
    bg_grad.setColorAt(0.0, QColor("#2A2212"))
    bg_grad.setColorAt(0.5, QColor("#161410"))
    bg_grad.setColorAt(1.0, QColor("#0D0E12"))
    painter.fillPath(path, bg_grad)

    gold_grad = QLinearGradient(0, s * 0.08, s, s * 0.92)
    gold_grad.setColorAt(0.0, QColor("#FDE68A"))
    gold_grad.setColorAt(0.5, QColor("#F59E0B"))
    gold_grad.setColorAt(1.0, QColor("#B45309"))
    pen = QPen(gold_grad, max(2.0, s * 0.065))
    pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
    painter.setPen(pen)
    painter.drawPath(path)

    # Inner shield crest
    inner = QPainterPath()
    inner.moveTo(s * 0.50, s * 0.22)
    inner.lineTo(s * 0.72, s * 0.31)
    inner.cubicTo(s * 0.72, s * 0.52, s * 0.62, s * 0.67, s * 0.50, s * 0.77)
    inner.cubicTo(s * 0.38, s * 0.67, s * 0.28, s * 0.52, s * 0.28, s * 0.31)
    inner.closeSubpath()
    painter.fillPath(inner, gold_grad)

    painter.end()
    return pix


class ShieldLogoWidget(QWidget):
    """Compact golden shield emblem widget for the top navigation bar."""

    def __init__(self, size: int = 28, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._size = size
        self.setFixedSize(size, size)

    def paintEvent(self, event) -> None:  # type: ignore[override]
        painter = QPainter(self)
        pix = render_shield_pixmap(self._size)
        painter.drawPixmap(0, 0, pix)
        painter.end()


class PortOverviewGaugeWidget(QWidget):
    """
    Circular glowing donut gauge + 3-column Open/Closed/Filtered legend
    matching the 'Network Port Overview' panel in Photo 1.
    """

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.open_ports: int = 247
        self.closed_ports: int = 1201
        self.filtered_ports: int = 34
        self.setMinimumSize(250, 235)

    def set_counts(self, open_ports: int, closed_ports: int, filtered_ports: int) -> None:
        self.open_ports = max(0, int(open_ports))
        self.closed_ports = max(0, int(closed_ports))
        self.filtered_ports = max(0, int(filtered_ports))
        self.update()

    def paintEvent(self, event) -> None:  # type: ignore[override]
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)

        w = float(self.width())
        h = float(self.height())

        legend_h = 56.0
        avail_h = max(110.0, h - legend_h - 8.0)
        diam = min(w - 44.0, avail_h - 14.0)
        diam = max(96.0, min(diam, 168.0))
        cx = w * 0.5
        cy = avail_h * 0.50
        rect = QRectF(cx - diam * 0.5, cy - diam * 0.5, diam, diam)

        # Subtle golden radial glow behind gauge
        glow = QRadialGradient(QPointF(cx, cy), diam * 0.62)
        glow.setColorAt(0.0, QColor(245, 158, 11, 28))
        glow.setColorAt(0.7, QColor(245, 158, 11, 10))
        glow.setColorAt(1.0, QColor(0, 0, 0, 0))
        painter.setBrush(glow)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawEllipse(QPointF(cx, cy), diam * 0.62, diam * 0.62)

        # Outer & inner decorative dark rings
        outer_pen = QPen(QColor("#262B36"), 1.5)
        painter.setPen(outer_pen)
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawEllipse(rect.adjusted(-7, -7, 7, 7))
        painter.drawEllipse(rect.adjusted(12, 12, -12, -12))

        # Base dark track ring
        ring_width = max(10.0, diam * 0.085)
        track_pen = QPen(QColor("#2A2F3A"), ring_width)
        track_pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(track_pen)
        painter.drawEllipse(rect)

        total = max(1, self.open_ports + self.closed_ports + self.filtered_ports)
        # Ensure visible golden arc even when open_ports is small
        open_ratio = min(0.78, max(0.28 if self.open_ports > 0 else 0.18, self.open_ports / total))
        span_deg = -int(open_ratio * 360 * 16)
        start_deg = 135 * 16

        # Outer soft glow for golden arc
        glow_pen = QPen(QColor(251, 191, 36, 70), ring_width + 6.0)
        glow_pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(glow_pen)
        painter.drawArc(rect, start_deg, span_deg)

        # Main bright gold arc
        arc_grad = QLinearGradient(rect.topLeft(), rect.bottomRight())
        arc_grad.setColorAt(0.0, QColor("#FDE047"))
        arc_grad.setColorAt(0.5, QColor("#F59E0B"))
        arc_grad.setColorAt(1.0, QColor("#D97706"))
        gold_pen = QPen(arc_grad, ring_width)
        gold_pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(gold_pen)
        painter.drawArc(rect, start_deg, span_deg)

        # Center text: big count + 'Ports'
        painter.setPen(QColor("#F8FAFC"))
        num_font = QFont("Segoe UI", 21, QFont.Weight.Bold)
        painter.setFont(num_font)
        painter.drawText(
            QRectF(cx - 60, cy - 22, 120, 30),
            Qt.AlignmentFlag.AlignCenter,
            f"{self.open_ports}",
        )

        painter.setPen(QColor("#94A3B8"))
        sub_font = QFont("Segoe UI", 10, QFont.Weight.Medium)
        painter.setFont(sub_font)
        painter.drawText(
            QRectF(cx - 50, cy + 8, 100, 20),
            Qt.AlignmentFlag.AlignCenter,
            "Ports",
        )

        # Bottom 3 columns: Open | Closed | Filtered
        base_y = h - legend_h + 4.0
        col_w = w / 3.0
        items = [
            ("Open", self.open_ports, QColor("#FBBF24")),
            ("Closed", self.closed_ports, QColor("#B45309")),
            ("Filtered", self.filtered_ports, QColor("#64748B")),
        ]
        lbl_font = QFont("Segoe UI", 9, QFont.Weight.Medium)
        val_font = QFont("Segoe UI", 12, QFont.Weight.Bold)

        for idx, (label, val, dot_color) in enumerate(items):
            x0 = idx * col_w + 10.0
            # Colored dot
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(dot_color)
            painter.drawEllipse(QPointF(x0 + 5.0, base_y + 8.0), 4.0, 4.0)

            # Label
            painter.setFont(lbl_font)
            painter.setPen(QColor("#CBD5E1"))
            painter.drawText(
                QRectF(x0 + 13.0, base_y - 1.0, col_w - 16.0, 18.0),
                Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                label,
            )

            # Value
            painter.setFont(val_font)
            painter.setPen(QColor("#F8FAFC"))
            painter.drawText(
                QRectF(x0 + 2.0, base_y + 18.0, col_w - 8.0, 22.0),
                Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                f"{val}",
            )

        # Golden accent bar at the very bottom left under Open/Closed
        bar_y = h - 6.0
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor("#262B36"))
        painter.drawRoundedRect(QRectF(10.0, bar_y, w - 20.0, 3.5), 2.0, 2.0)

        bar_grad = QLinearGradient(10.0, bar_y, w * 0.55, bar_y)
        bar_grad.setColorAt(0.0, QColor("#FDE047"))
        bar_grad.setColorAt(1.0, QColor("#D97706"))
        painter.setBrush(bar_grad)
        painter.drawRoundedRect(QRectF(10.0, bar_y, (w - 20.0) * 0.44, 3.5), 2.0, 2.0)

        painter.end()


class RealtimePacketFlowChart(QWidget):
    """
    Dual-axis smooth spline area chart ('Real-Time Packet Flow') with glowing
    TCP & UDP curves, vertical dashed peak drop-lines, and callout badges (Photo 1).
    """

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._samples: List[TrafficSample] = []
        self._hover_x: Optional[float] = None
        self.setMouseTracking(True)
        self.setMinimumSize(380, 235)

    def set_samples(self, samples: Sequence[TrafficSample]) -> None:
        self._samples = list(samples)[-28:]
        self.update()

    def mouseMoveEvent(self, event) -> None:  # type: ignore[override]
        self._hover_x = float(event.position().x())
        self.update()

    def leaveEvent(self, event) -> None:  # type: ignore[override]
        self._hover_x = None
        self.update()

    @staticmethod
    def _build_smooth_path(points: List[QPointF]) -> QPainterPath:
        path = QPainterPath()
        if not points:
            return path
        path.moveTo(points[0])
        if len(points) == 1:
            return path
        for i in range(len(points) - 1):
            p0 = points[i]
            p1 = points[i + 1]
            mid_x = (p0.x() + p1.x()) * 0.5
            path.cubicTo(QPointF(mid_x, p0.y()), QPointF(mid_x, p1.y()), p1)
        return path

    def paintEvent(self, event) -> None:  # type: ignore[override]
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)

        w = float(self.width())
        h = float(self.height())

        left_pad = 44.0
        right_pad = 50.0
        top_pad = 16.0
        bottom_pad = 34.0
        plot_w = max(80.0, w - left_pad - right_pad)
        plot_h = max(80.0, h - top_pad - bottom_pad)
        plot_rect = QRectF(left_pad, top_pad, plot_w, plot_h)

        # Horizontal & vertical subtle grid lines
        grid_pen = QPen(QColor("#222631"), 1.0)
        painter.setPen(grid_pen)
        y_ticks = [0, 50, 100, 200, 400, 500]
        r_ticks = [0, 5000, 10000, 15000, 20000, 25000]
        axis_font = QFont("Segoe UI", 8)
        painter.setFont(axis_font)

        n_rows = len(y_ticks) - 1
        for i, y_val in enumerate(reversed(y_ticks)):
            ry = top_pad + (i / n_rows) * plot_h
            painter.setPen(grid_pen)
            painter.drawLine(QPointF(left_pad, ry), QPointF(left_pad + plot_w, ry))

            # Left Y-axis label (Mbps)
            painter.setPen(QColor("#94A3B8"))
            painter.drawText(
                QRectF(4.0, ry - 8.0, left_pad - 8.0, 16.0),
                Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
                str(y_val),
            )

            # Right Y-axis label (packets/s)
            r_val = r_ticks[n_rows - i]
            painter.drawText(
                QRectF(left_pad + plot_w + 6.0, ry - 8.0, right_pad - 8.0, 16.0),
                Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                str(r_val),
            )

        # Vertical grid lines
        cols = 6
        for c in range(cols + 1):
            rx = left_pad + (c / cols) * plot_w
            painter.setPen(grid_pen)
            painter.drawLine(QPointF(rx, top_pad), QPointF(rx, top_pad + plot_h))

        # Rotated Y-axis titles (Mbps & packets/s)
        painter.save()
        painter.setPen(QColor("#64748B"))
        painter.translate(11.0, top_pad + plot_h * 0.5)
        painter.rotate(-90)
        painter.drawText(QRectF(-40, -8, 80, 16), Qt.AlignmentFlag.AlignCenter, "Mbps")
        painter.restore()

        painter.save()
        painter.setPen(QColor("#64748B"))
        painter.translate(w - 8.0, top_pad + plot_h * 0.5)
        painter.rotate(-90)
        painter.drawText(QRectF(-45, -8, 90, 16), Qt.AlignmentFlag.AlignCenter, "packets/s")
        painter.restore()

        if not self._samples:
            painter.end()
            return

        n = len(self._samples)
        max_val = max(
            320.0,
            max((max(s.tcp_mbps, s.udp_mbps) * 1.25 for s in self._samples), default=320.0),
        )

        tcp_pts: List[QPointF] = []
        udp_pts: List[QPointF] = []
        for idx, s in enumerate(self._samples):
            x = left_pad + (idx / max(1, n - 1)) * plot_w
            ty = top_pad + plot_h - min(1.0, max(0.04, s.tcp_mbps / max_val)) * plot_h
            uy = top_pad + plot_h - min(1.0, max(0.04, s.udp_mbps / max_val)) * plot_h
            tcp_pts.append(QPointF(x, ty))
            udp_pts.append(QPointF(x, uy))

        # Draw X-axis time labels (use HH:MM:SS if adjacent ticks share the same HH:MM)
        step = max(1, (n - 1) // 6)
        tick_indices = list(range(0, n, step))
        short_labels = [self._samples[i].timestamp[:5] for i in tick_indices]
        has_dup_min = len(set(short_labels)) < len(short_labels)
        painter.setPen(QColor("#94A3B8"))
        for idx in tick_indices:
            x = left_pad + (idx / max(1, n - 1)) * plot_w
            raw_ts = self._samples[idx].timestamp
            ts_lbl = raw_ts if (has_dup_min and len(raw_ts) > 5) else raw_ts[:5]
            painter.drawText(
                QRectF(x - 28.0, top_pad + plot_h + 4.0, 56.0, 16.0),
                Qt.AlignmentFlag.AlignCenter,
                ts_lbl,
            )

        painter.setPen(QColor("#CBD5E1"))
        painter.drawText(
            QRectF(left_pad, h - 16.0, plot_w, 15.0),
            Qt.AlignmentFlag.AlignCenter,
            "Time",
        )

        # Build smooth paths and area fills
        tcp_path = self._build_smooth_path(tcp_pts)
        udp_path = self._build_smooth_path(udp_pts)

        tcp_area = QPainterPath(tcp_path)
        tcp_area.lineTo(tcp_pts[-1].x(), top_pad + plot_h)
        tcp_area.lineTo(tcp_pts[0].x(), top_pad + plot_h)
        tcp_area.closeSubpath()

        tcp_grad = QLinearGradient(0, top_pad, 0, top_pad + plot_h)
        tcp_grad.setColorAt(0.0, QColor(234, 88, 12, 110))
        tcp_grad.setColorAt(0.65, QColor(245, 158, 11, 35))
        tcp_grad.setColorAt(1.0, QColor(245, 158, 11, 4))
        painter.fillPath(tcp_area, tcp_grad)

        udp_area = QPainterPath(udp_path)
        udp_area.lineTo(udp_pts[-1].x(), top_pad + plot_h)
        udp_area.lineTo(udp_pts[0].x(), top_pad + plot_h)
        udp_area.closeSubpath()

        udp_grad = QLinearGradient(0, top_pad, 0, top_pad + plot_h)
        udp_grad.setColorAt(0.0, QColor(251, 191, 36, 95))
        udp_grad.setColorAt(0.7, QColor(251, 191, 36, 25))
        udp_grad.setColorAt(1.0, QColor(251, 191, 36, 2))
        painter.fillPath(udp_area, udp_grad)

        # Draw glowing lines
        painter.setPen(QPen(QColor(234, 88, 12, 85), 4.5))
        painter.drawPath(tcp_path)
        painter.setPen(QPen(QColor("#FB923C"), 2.0))
        painter.drawPath(tcp_path)

        painter.setPen(QPen(QColor(250, 204, 21, 80), 4.5))
        painter.drawPath(udp_path)
        painter.setPen(QPen(QColor("#FDE047"), 2.0))
        painter.drawPath(udp_path)

        # Peak callout badges with vertical dashed lines (matching Photo 1)
        if n >= 6:
            peak_tcp_idx = max(range(n // 4, n - 1), key=lambda i: self._samples[i].tcp_mbps)
            peak_udp_idx = max(
                range(n // 3, n),
                key=lambda i: self._samples[i].udp_mbps if i != peak_tcp_idx else -1.0,
            )
            self._draw_callout(
                painter,
                tcp_pts[peak_tcp_idx],
                plot_rect.bottom(),
                "TCP Traffic",
                QColor("#EF4444"),
                QColor("#FCA5A5"),
            )
            self._draw_callout(
                painter,
                udp_pts[peak_udp_idx],
                plot_rect.bottom(),
                "UDP Activity",
                QColor("#F59E0B"),
                QColor("#FDE68A"),
            )

        # Interactive hover crosshair
        if self._hover_x is not None and left_pad <= self._hover_x <= left_pad + plot_w:
            rel = (self._hover_x - left_pad) / plot_w
            h_idx = min(n - 1, max(0, int(round(rel * (n - 1)))))
            hx = tcp_pts[h_idx].x()
            dash_pen = QPen(QColor("#FBBF24"), 1.0, Qt.PenStyle.DashLine)
            painter.setPen(dash_pen)
            painter.drawLine(QPointF(hx, top_pad), QPointF(hx, top_pad + plot_h))

            s = self._samples[h_idx]
            tip_text = f"{s.timestamp} | TCP: {s.tcp_mbps:.1f} Mbps | UDP: {s.udp_mbps:.1f} Mbps"
            tip_w = 230.0
            tip_x = min(max(left_pad + 4.0, hx - tip_w * 0.5), left_pad + plot_w - tip_w - 4.0)
            tip_rect = QRectF(tip_x, top_pad + 4.0, tip_w, 22.0)
            painter.setPen(QPen(QColor("#F59E0B"), 1.0))
            painter.setBrush(QColor(17, 20, 28, 230))
            painter.drawRoundedRect(tip_rect, 5.0, 5.0)
            painter.setPen(QColor("#F8FAFC"))
            painter.setFont(QFont("Segoe UI", 8, QFont.Weight.DemiBold))
            painter.drawText(tip_rect, Qt.AlignmentFlag.AlignCenter, tip_text)

        painter.end()

    @staticmethod
    def _draw_callout(
        painter: QPainter,
        pt: QPointF,
        bottom_y: float,
        label: str,
        accent: QColor,
        text_color: QColor,
    ) -> None:
        # Dashed drop-line to X-axis
        dash = QPen(accent, 1.1, Qt.PenStyle.DashLine)
        painter.setPen(dash)
        painter.drawLine(pt, QPointF(pt.x(), bottom_y))

        # Glowing dot at peak
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(accent)
        painter.drawEllipse(pt, 4.5, 4.5)
        painter.setBrush(QColor("#FFFBEB"))
        painter.drawEllipse(pt, 2.0, 2.0)

        # Callout pill box above or beside peak
        box_w = 78.0
        box_h = 20.0
        bx = max(48.0, min(pt.x() - box_w * 0.5, pt.x() - 10.0))
        by = max(14.0, pt.y() - 28.0)
        box_rect = QRectF(bx, by, box_w, box_h)

        painter.setPen(QPen(accent, 1.0))
        painter.setBrush(QColor(24, 24, 32, 220))
        painter.drawRoundedRect(box_rect, 4.0, 4.0)

        painter.setPen(text_color)
        painter.setFont(QFont("Segoe UI", 8, QFont.Weight.DemiBold))
        painter.drawText(box_rect, Qt.AlignmentFlag.AlignCenter, label)


class TopProtocolsBarChart(QWidget):
    """
    Vertical glowing gold bar chart ('Top Protocols': TCP 65%, UDP 22%, HTTP 8%, SSH 5%)
    matching the right-middle panel of Photo 1.
    """

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._protocols: List[Tuple[str, int]] = [
            ("TCP", 65),
            ("UDP", 22),
            ("HTTP", 8),
            ("SSH", 5),
        ]
        self.setMinimumSize(220, 235)

    def set_protocols(self, protocols: Sequence[Tuple[str, int]]) -> None:
        if protocols:
            self._protocols = list(protocols)[:4]
            self.update()

    def paintEvent(self, event) -> None:  # type: ignore[override]
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)

        w = float(self.width())
        h = float(self.height())

        top_pad = 24.0
        bottom_pad = 54.0
        side_pad = 18.0
        plot_h = max(80.0, h - top_pad - bottom_pad)
        plot_w = max(100.0, w - side_pad * 2)

        # Subtle horizontal grid lines
        grid_pen = QPen(QColor("#232733"), 1.0)
        painter.setPen(grid_pen)
        for i in range(4):
            gy = top_pad + (i / 3.0) * plot_h
            painter.drawLine(QPointF(side_pad, gy), QPointF(w - side_pad, gy))

        n = max(1, len(self._protocols))
        slot_w = plot_w / n
        bar_w = min(36.0, slot_w * 0.56)
        max_pct = max(75, max((pct for _, pct in self._protocols), default=65))

        for idx, (name, pct) in enumerate(self._protocols):
            cx = side_pad + (idx + 0.5) * slot_w
            bh = max(12.0, (pct / max_pct) * (plot_h - 14.0))
            bx = cx - bar_w * 0.5
            by = top_pad + plot_h - bh
            bar_rect = QRectF(bx, by, bar_w, bh)

            # Bar gradient fill
            grad = QLinearGradient(0, by, 0, by + bh)
            grad.setColorAt(0.0, QColor(251, 191, 36, 175))
            grad.setColorAt(0.5, QColor(217, 119, 6, 110))
            grad.setColorAt(1.0, QColor(120, 53, 15, 45))
            painter.setBrush(grad)
            painter.setPen(QPen(QColor("#FBBF24"), 1.5))
            painter.drawRoundedRect(bar_rect, 3.0, 3.0)

            # Label above bar
            painter.setPen(QColor("#CBD5E1"))
            painter.setFont(QFont("Segoe UI", 8, QFont.Weight.DemiBold))
            painter.drawText(
                QRectF(cx - slot_w * 0.5, by - 18.0, slot_w, 16.0),
                Qt.AlignmentFlag.AlignCenter,
                name,
            )

            # Protocol name below baseline
            painter.setPen(QColor("#CBD5E1"))
            painter.setFont(QFont("Segoe UI", 9, QFont.Weight.Medium))
            painter.drawText(
                QRectF(cx - slot_w * 0.5, top_pad + plot_h + 6.0, slot_w, 18.0),
                Qt.AlignmentFlag.AlignCenter,
                name,
            )

            # Bold percentage below name
            painter.setPen(QColor("#F8FAFC"))
            painter.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
            painter.drawText(
                QRectF(cx - slot_w * 0.5, top_pad + plot_h + 24.0, slot_w, 20.0),
                Qt.AlignmentFlag.AlignCenter,
                f"{pct}%",
            )

        # Bottom golden highlight line
        bar_y = h - 6.0
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor("#262B36"))
        painter.drawRoundedRect(QRectF(side_pad, bar_y, plot_w, 3.0), 1.5, 1.5)
        gold_line = QLinearGradient(side_pad, bar_y, side_pad + plot_w * 0.7, bar_y)
        gold_line.setColorAt(0.0, QColor("#262B36"))
        gold_line.setColorAt(0.5, QColor("#FDE047"))
        gold_line.setColorAt(1.0, QColor("#262B36"))
        painter.setBrush(gold_line)
        painter.drawRoundedRect(QRectF(side_pad, bar_y, plot_w, 3.0), 1.5, 1.5)

        painter.end()


class FlowsSpiralWidget(QWidget):
    """
    Radial spiral time-series heatmap ('Flows Spiral') from Photo 2.
    Renders concentric spiral turns, radial minute ticks (0..55), heat-colored slices,
    cyan spiral guide line, and color scale legend.
    """

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._intensities: List[float] = [0.35 + 0.55 * (math.sin(i * 0.25) * 0.5 + 0.5) for i in range(96)]
        self.setMinimumSize(320, 340)

    def set_intensities(self, values: Sequence[float]) -> None:
        if values:
            base = list(values)
            while len(base) < 96:
                base.extend(values)
            self._intensities = base[:96]
            self.update()

    @staticmethod
    def _heat_color(val: float) -> QColor:
        v = min(1.0, max(0.0, val))
        if v >= 0.72:
            return QColor("#F43F5E")  # Coral Red peak
        if v >= 0.48:
            return QColor("#FB923C")  # Warm Orange
        if v >= 0.25:
            return QColor("#FACC15")  # Golden Yellow
        return QColor("#22C55E")      # Emerald Low

    def paintEvent(self, event) -> None:  # type: ignore[override]
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)

        w = float(self.width())
        h = float(self.height())
        cx = w * 0.50
        cy = h * 0.51
        max_r = min(w, h) * 0.37

        # Subtitle date range at top
        painter.setPen(QColor("#94A3B8"))
        painter.setFont(QFont("Segoe UI", 8))
        painter.drawText(
            QRectF(0, 6.0, w, 16.0),
            Qt.AlignmentFlag.AlignCenter,
            "Real-Time Spiral Window (60-Min Radial Projection)",
        )

        # Radial background guide lines & outer minute labels (0, 5, 10 ... 55)
        ring_pen = QPen(QColor("#222630"), 1.0)
        for frac in (0.28, 0.48, 0.68, 0.88, 1.0):
            painter.setPen(ring_pen)
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawEllipse(QPointF(cx, cy), max_r * frac, max_r * frac)

        for minute in range(0, 60, 5):
            angle_deg = minute * 6.0 - 90.0
            rad = math.radians(angle_deg)
            x1 = cx + math.cos(rad) * (max_r * 0.20)
            y1 = cy + math.sin(rad) * (max_r * 0.20)
            x2 = cx + math.cos(rad) * (max_r * 1.03)
            y2 = cy + math.sin(rad) * (max_r * 1.03)
            painter.setPen(QPen(QColor("#1E222B"), 1.0))
            painter.drawLine(QPointF(x1, y1), QPointF(x2, y2))

            lx = cx + math.cos(rad) * (max_r * 1.13)
            ly = cy + math.sin(rad) * (max_r * 1.13)
            painter.setPen(QColor("#94A3B8"))
            painter.setFont(QFont("Segoe UI", 8))
            painter.drawText(
                QRectF(lx - 14.0, ly - 8.0, 28.0, 16.0),
                Qt.AlignmentFlag.AlignCenter,
                str(minute),
            )

        # Draw continuous cyan spiral spine + colored radial bars along 3.2 turns
        total_steps = len(self._intensities)
        turns = 3.2
        min_r = max_r * 0.16
        spine_pts: List[QPointF] = []

        for i, intensity in enumerate(self._intensities):
            t = i / max(1, total_steps - 1)
            theta = t * turns * 2.0 * math.pi - math.pi * 0.5
            r_mid = min_r + t * (max_r * 0.80)
            spine_pts.append(QPointF(cx + math.cos(theta) * r_mid, cy + math.sin(theta) * r_mid))

            # Draw radial block segment
            bar_thick = (4.0 + intensity * 12.0) * (0.55 + 0.45 * t)
            r_in = r_mid - bar_thick * 0.35
            r_out = r_mid + bar_thick * 0.65
            d_theta = (turns * 2.0 * math.pi / total_steps) * 0.78

            p1 = QPointF(cx + math.cos(theta - d_theta * 0.5) * r_in, cy + math.sin(theta - d_theta * 0.5) * r_in)
            p2 = QPointF(cx + math.cos(theta - d_theta * 0.5) * r_out, cy + math.sin(theta - d_theta * 0.5) * r_out)
            p3 = QPointF(cx + math.cos(theta + d_theta * 0.5) * r_out, cy + math.sin(theta + d_theta * 0.5) * r_out)
            p4 = QPointF(cx + math.cos(theta + d_theta * 0.5) * r_in, cy + math.sin(theta + d_theta * 0.5) * r_in)

            poly = QPolygonF([p1, p2, p3, p4])
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(self._heat_color(intensity))
            painter.drawPolygon(poly)

        # Cyan spiral guide curve
        if len(spine_pts) > 1:
            spine_path = QPainterPath()
            spine_path.moveTo(spine_pts[0])
            for pt in spine_pts[1:]:
                spine_path.lineTo(pt)
            painter.setPen(QPen(QColor(56, 189, 248, 180), 1.2))
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawPath(spine_path)

        # Hour labels along vertical center axis (01:00, 23:00, 22:00, 21:00)
        ring_labels = [("01:00", 0.90), ("23:00", 0.66), ("22:00", 0.44), ("21:00", 0.22)]
        painter.setFont(QFont("Segoe UI", 7, QFont.Weight.Bold))
        for txt, frac in ring_labels:
            ly = cy - max_r * frac
            bg_r = QRectF(cx - 18.0, ly - 7.0, 36.0, 14.0)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor(15, 17, 23, 210))
            painter.drawRoundedRect(bg_r, 3.0, 3.0)
            painter.setPen(QColor("#E2E8F0"))
            painter.drawText(bg_r, Qt.AlignmentFlag.AlignCenter, txt)

        # Bottom-left color scale bar (25k, 12k, 14)
        leg_x = 14.0
        leg_y = h - 48.0
        colors = [QColor("#F43F5E"), QColor("#FB923C"), QColor("#FACC15"), QColor("#22C55E")]
        for idx, col in enumerate(colors):
            painter.setBrush(col)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.drawRect(QRectF(leg_x, leg_y + idx * 7.5, 6.0, 6.5))

        painter.setPen(QColor("#94A3B8"))
        painter.setFont(QFont("Segoe UI", 7))
        painter.drawText(QRectF(leg_x + 10.0, leg_y - 3.0, 35.0, 12.0), Qt.AlignmentFlag.AlignLeft, "25 k")
        painter.drawText(QRectF(leg_x + 10.0, leg_y + 10.0, 35.0, 12.0), Qt.AlignmentFlag.AlignLeft, "12 k")
        painter.drawText(QRectF(leg_x + 10.0, leg_y + 22.0, 35.0, 12.0), Qt.AlignmentFlag.AlignLeft, "14")

        # Bottom caption
        painter.setPen(QColor("#E2E8F0"))
        painter.setFont(QFont("Segoe UI", 8, QFont.Weight.DemiBold))
        painter.drawText(
            QRectF(0, h - 20.0, w, 16.0),
            Qt.AlignmentFlag.AlignCenter,
            "Slice: a minute",
        )

        painter.end()


class TelemetryAreaChart(QWidget):
    """
    Compact telemetry area chart used in the 6 side panels of Photo 2 ('Analyze' tab):
    Bitrate, Packets Rate, Flow Rate, Source IP Cardinality, Site, and Source Vendor/Country.
    Supports synchronized hover and dark callout badges.
    """

    hovered_ratio_changed = Signal(object)  # float or None

    def __init__(
        self,
        title: str,
        unit: str,
        accent_color: str,
        y_labels: Sequence[str],
        legend_items: Optional[Sequence[Tuple[str, str]]] = None,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self.title = title
        self.unit = unit
        self.accent_color = QColor(accent_color)
        self.y_labels = list(y_labels)
        self.legend_items = list(legend_items) if legend_items else []
        self._values: List[float] = []
        self._secondary_values: List[float] = []
        self._timestamps: List[str] = []
        self._callout_title: str = ""
        self._callout_rows: List[Tuple[str, str, str]] = []
        self._hover_ratio: Optional[float] = None
        self.setMouseTracking(True)
        self.setMinimumSize(240, 125)

    def set_series(
        self,
        values: Sequence[float],
        timestamps: Sequence[str],
        callout_title: str,
        callout_rows: Sequence[Tuple[str, str, str]],
        secondary_values: Optional[Sequence[float]] = None,
    ) -> None:
        self._values = list(values)[-36:]
        self._timestamps = list(timestamps)[-36:]
        self._callout_title = callout_title
        self._callout_rows = list(callout_rows)
        self._secondary_values = list(secondary_values)[-36:] if secondary_values else []
        self.update()

    def set_hover_ratio(self, ratio: Optional[float]) -> None:
        self._hover_ratio = ratio
        self.update()

    def mouseMoveEvent(self, event) -> None:  # type: ignore[override]
        w = float(self.width())
        left_pad = 48.0
        right_pad = 12.0
        plot_w = max(60.0, w - left_pad - right_pad)
        rx = float(event.position().x())
        if left_pad <= rx <= left_pad + plot_w:
            ratio = (rx - left_pad) / plot_w
            self._hover_ratio = ratio
            self.hovered_ratio_changed.emit(ratio)
            self.update()

    def leaveEvent(self, event) -> None:  # type: ignore[override]
        self._hover_ratio = None
        self.hovered_ratio_changed.emit(None)
        self.update()

    def paintEvent(self, event) -> None:  # type: ignore[override]
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)

        w = float(self.width())
        h = float(self.height())
        left_pad = 50.0
        right_pad = 10.0
        top_pad = 24.0
        bottom_pad = 34.0 if self.legend_items else 20.0
        plot_w = max(60.0, w - left_pad - right_pad)
        plot_h = max(45.0, h - top_pad - bottom_pad)

        # Panel Title with filter funnel icon prefix
        painter.setPen(QColor("#94A3B8"))
        painter.setFont(QFont("Segoe UI", 8, QFont.Weight.Bold))
        painter.drawText(QRectF(8.0, 4.0, 14.0, 16.0), Qt.AlignmentFlag.AlignLeft, "▼")
        painter.setPen(QColor("#F1F5F9"))
        painter.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        painter.drawText(QRectF(22.0, 3.0, w - 30.0, 16.0), Qt.AlignmentFlag.AlignLeft, self.title)

        # Grid lines & Y labels
        n_y = max(1, len(self.y_labels) - 1)
        painter.setFont(QFont("Segoe UI", 7))
        for idx, y_txt in enumerate(self.y_labels):
            gy = top_pad + (idx / n_y) * plot_h
            painter.setPen(QPen(QColor("#222630"), 1.0))
            painter.drawLine(QPointF(left_pad, gy), QPointF(left_pad + plot_w, gy))
            painter.setPen(QColor("#64748B"))
            painter.drawText(
                QRectF(2.0, gy - 7.0, left_pad - 6.0, 14.0),
                Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
                y_txt,
            )

        if self._values:
            n = len(self._values)
            sec_max = max(self._secondary_values) if self._secondary_values else 0.0
            max_v = max(1.0, max(max(self._values), sec_max) * 1.25)
            pts: List[QPointF] = []
            for i, v in enumerate(self._values):
                px = left_pad + (i / max(1, n - 1)) * plot_w
                py = top_pad + plot_h - min(1.0, max(0.02, v / max_v)) * plot_h
                pts.append(QPointF(px, py))

            path = RealtimePacketFlowChart._build_smooth_path(pts)
            area = QPainterPath(path)
            area.lineTo(pts[-1].x(), top_pad + plot_h)
            area.lineTo(pts[0].x(), top_pad + plot_h)
            area.closeSubpath()

            grad = QLinearGradient(0, top_pad, 0, top_pad + plot_h)
            c_top = QColor(self.accent_color)
            c_top.setAlpha(125)
            c_bot = QColor(self.accent_color)
            c_bot.setAlpha(10)
            grad.setColorAt(0.0, c_top)
            grad.setColorAt(1.0, c_bot)
            painter.fillPath(area, grad)

            painter.setPen(QPen(self.accent_color, 1.6))
            painter.drawPath(path)

            # Draw secondary curve if present (e.g., Gateway / secondary vendor series)
            if self._secondary_values and len(self._secondary_values) == n:
                sec_pts: List[QPointF] = []
                for i, sv in enumerate(self._secondary_values):
                    px = left_pad + (i / max(1, n - 1)) * plot_w
                    py = top_pad + plot_h - min(1.0, max(0.02, sv / max_v)) * plot_h
                    sec_pts.append(QPointF(px, py))
                sec_path = RealtimePacketFlowChart._build_smooth_path(sec_pts)
                sec_col = (
                    QColor(self.legend_items[1][1])
                    if len(self.legend_items) > 1
                    else QColor("#22C55E")
                )
                painter.setPen(QPen(sec_col, 1.3, Qt.PenStyle.SolidLine))
                painter.drawPath(sec_path)

            # Time labels on X-axis
            if self._timestamps:
                painter.setPen(QColor("#64748B"))
                painter.setFont(QFont("Segoe UI", 7))
                for frac in (0.15, 0.45, 0.75, 0.96):
                    ti = min(len(self._timestamps) - 1, int(frac * (len(self._timestamps) - 1)))
                    tx = left_pad + frac * plot_w
                    painter.drawText(
                        QRectF(tx - 20.0, top_pad + plot_h + 2.0, 40.0, 13.0),
                        Qt.AlignmentFlag.AlignCenter,
                        self._timestamps[ti][:5],
                    )

            # Synchronized hover vertical line + marker dot on curve
            if self._hover_ratio is not None:
                clamped_r = min(1.0, max(0.0, self._hover_ratio))
                hx = left_pad + clamped_r * plot_w
                painter.setPen(QPen(QColor("#38BDF8"), 1.0, Qt.PenStyle.DashLine))
                painter.drawLine(QPointF(hx, top_pad), QPointF(hx, top_pad + plot_h))

                h_idx = min(n - 1, max(0, int(round(clamped_r * (n - 1)))))
                h_pt = pts[h_idx]
                painter.setPen(Qt.PenStyle.NoPen)
                painter.setBrush(self.accent_color)
                painter.drawEllipse(h_pt, 3.5, 3.5)
                painter.setBrush(QColor("#F8FAFC"))
                painter.drawEllipse(h_pt, 1.5, 1.5)

        # Bottom legend pills if configured
        if self.legend_items:
            lx = left_pad
            ly = h - 17.0
            painter.setFont(QFont("Segoe UI", 7, QFont.Weight.DemiBold))
            for lbl, col_hex in self.legend_items:
                pill_w = max(36.0, len(lbl) * 5.8 + 18.0)
                if lx + pill_w > w - right_pad:
                    break
                r_pill = QRectF(lx, ly, pill_w, 15.0)
                painter.setPen(QPen(QColor("#2A2F3A"), 1.0))
                painter.setBrush(QColor("#161922"))
                painter.drawRoundedRect(r_pill, 3.0, 3.0)

                painter.setPen(QPen(QColor(col_hex), 2.0))
                painter.drawLine(QPointF(lx + 5.0, ly + 7.5), QPointF(lx + 11.0, ly + 7.5))

                painter.setPen(QColor("#CBD5E1"))
                painter.drawText(
                    QRectF(lx + 14.0, ly, pill_w - 16.0, 15.0),
                    Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                    lbl,
                )
                lx += pill_w + 5.0

        # Floating dark callout box (Photo 2 style, hover-reactive & compact-height safe)
        if self._callout_rows:
            active_title = self._callout_title
            active_rows = list(self._callout_rows)

            if self._hover_ratio is not None and self._values:
                n = len(self._values)
                h_idx = min(n - 1, max(0, int(round(min(1.0, max(0.0, self._hover_ratio)) * (n - 1)))))
                if self._timestamps and h_idx < len(self._timestamps):
                    date_prefix = self._callout_title[:11] if len(self._callout_title) >= 11 else ""
                    active_title = f"{date_prefix}{self._timestamps[h_idx][:5]}".strip()
                last_val = max(0.001, self._values[-1])
                scale_r = self._values[h_idx] / last_val
                if len(active_rows) == 1:
                    r_name, _, r_col = active_rows[0]
                    hv = self._values[h_idx]
                    val_fmt = f"{int(round(hv))}" if self.unit == "IPs" else f"{hv:.2f} {self.unit}"
                    active_rows = [(r_name, val_fmt, r_col)]
                else:
                    updated_rows: List[Tuple[str, str, str]] = []
                    for r_idx, (r_name, r_val_str, r_col) in enumerate(active_rows):
                        if r_idx == 0:
                            hv = self._values[h_idx]
                            updated_rows.append((r_name, f"{hv:.1f} {self.unit}", r_col))
                        elif r_idx == 1 and self._secondary_values and h_idx < len(self._secondary_values):
                            sv = self._secondary_values[h_idx]
                            updated_rows.append((r_name, f"{sv:.1f} {self.unit}", r_col))
                        else:
                            parts = r_val_str.split()
                            try:
                                base_num = float(parts[0]) * scale_r
                                unit_sfx = parts[1] if len(parts) > 1 else self.unit
                                updated_rows.append((r_name, f"{base_num:.1f} {unit_sfx}", r_col))
                            except Exception:
                                updated_rows.append((r_name, r_val_str, r_col))
                    active_rows = updated_rows

            # Fit callout box cleanly inside plot_h even at compact 1024x600 window sizes
            avail_box_h = max(30.0, plot_h - 4.0)
            row_h = 12.5 if avail_box_h >= 72.0 else 10.5
            max_rows = max(1, int((avail_box_h - 16.0) // row_h))
            visible_rows = active_rows[:max_rows]

            box_h = 16.0 + len(visible_rows) * row_h
            box_w = 132.0
            bx = w - box_w - 12.0
            by = top_pad - 2.0
            box_rect = QRectF(bx, by, box_w, box_h)

            painter.setPen(QPen(QColor("#333846"), 1.0))
            painter.setBrush(QColor(18, 21, 28, 232))
            painter.drawRoundedRect(box_rect, 4.0, 4.0)

            painter.setPen(QColor("#F8FAFC"))
            painter.setFont(QFont("Segoe UI", 7, QFont.Weight.Bold))
            painter.drawText(
                QRectF(bx + 6.0, by + 2.0, box_w - 12.0, 12.0),
                Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                active_title,
            )

            painter.setFont(QFont("Segoe UI", 7))
            for r_idx, (name, val_str, col_hex) in enumerate(visible_rows):
                ry = by + 14.5 + r_idx * row_h
                painter.setPen(QPen(QColor(col_hex), 2.0))
                painter.drawLine(QPointF(bx + 6.0, ry + 5.5), QPointF(bx + 12.0, ry + 5.5))

                painter.setPen(QColor("#CBD5E1"))
                painter.drawText(
                    QRectF(bx + 15.0, ry, 58.0, row_h),
                    Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                    name,
                )
                painter.setPen(QColor("#F8FAFC"))
                painter.setFont(QFont("Segoe UI", 7, QFont.Weight.Bold))
                painter.drawText(
                    QRectF(bx + 62.0, ry, box_w - 68.0, row_h),
                    Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
                    val_str,
                )
                painter.setFont(QFont("Segoe UI", 7))

        painter.end()


class HorizontalBreakdownBarWidget(QWidget):
    """
    100% stacked horizontal breakdown bar ('Protocol Breakdown' & 'Port Breakdown')
    with 0..100 scale ticks and dark pill legend badges matching Photo 2.
    """

    def __init__(self, title: str, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.title = title
        self._segments: List[Tuple[str, float, str]] = []
        self.setMinimumSize(280, 96)

    def set_segments(self, segments: Sequence[Tuple[str, float, str]]) -> None:
        self._segments = list(segments)
        self.update()

    def paintEvent(self, event) -> None:  # type: ignore[override]
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)

        w = float(self.width())
        h = float(self.height())
        pad_x = 12.0
        bar_w = max(80.0, w - pad_x * 2)

        # Header title
        painter.setPen(QColor("#94A3B8"))
        painter.setFont(QFont("Segoe UI", 8, QFont.Weight.Bold))
        painter.drawText(QRectF(pad_x, 4.0, 14.0, 16.0), Qt.AlignmentFlag.AlignLeft, "▼")
        painter.setPen(QColor("#F1F5F9"))
        painter.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        painter.drawText(QRectF(pad_x + 14.0, 3.0, bar_w - 14.0, 16.0), Qt.AlignmentFlag.AlignLeft, self.title)

        # Stacked horizontal bar
        bar_y = 24.0
        bar_h = 18.0
        total = max(0.001, sum(pct for _, pct, _ in self._segments))
        cur_x = pad_x

        for idx, (label, pct, col_hex) in enumerate(self._segments):
            seg_w = (pct / total) * bar_w
            if idx == len(self._segments) - 1:
                seg_w = max(2.0, (pad_x + bar_w) - cur_x)
            painter.setPen(QPen(QColor("#111318"), 1.0))
            painter.setBrush(QColor(col_hex))
            painter.drawRect(QRectF(cur_x, bar_y, seg_w, bar_h))
            cur_x += seg_w

        # 0..100 ruler ticks
        ruler_y = bar_y + bar_h + 6.0
        painter.setPen(QPen(QColor("#262B36"), 1.0))
        painter.drawLine(QPointF(pad_x, ruler_y), QPointF(pad_x + bar_w, ruler_y))
        painter.setFont(QFont("Segoe UI", 7))
        for pct_tick in range(0, 101, 10):
            tx = pad_x + (pct_tick / 100.0) * bar_w
            painter.setPen(QColor("#2A2F3A"))
            painter.drawLine(QPointF(tx, ruler_y - 2.0), QPointF(tx, ruler_y + 2.0))
            painter.setPen(QColor("#64748B"))
            painter.drawText(
                QRectF(tx - 12.0, ruler_y + 3.0, 24.0, 12.0),
                Qt.AlignmentFlag.AlignCenter,
                str(pct_tick),
            )

        # Bottom legend pills
        lx = pad_x
        ly = h - 21.0
        painter.setFont(QFont("Segoe UI", 7, QFont.Weight.DemiBold))
        for label, _, col_hex in self._segments:
            pill_w = max(44.0, len(label) * 6.0 + 22.0)
            if lx + pill_w > w - pad_x:
                break
            r_pill = QRectF(lx, ly, pill_w, 16.0)
            painter.setPen(QPen(QColor("#2A2F3A"), 1.0))
            painter.setBrush(QColor("#161922"))
            painter.drawRoundedRect(r_pill, 3.0, 3.0)

            painter.setPen(QPen(QColor(col_hex), 2.2))
            painter.drawLine(QPointF(lx + 5.0, ly + 8.0), QPointF(lx + 11.0, ly + 8.0))

            painter.setPen(QColor("#E2E8F0"))
            painter.drawText(
                QRectF(lx + 15.0, ly, pill_w - 17.0, 16.0),
                Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                label,
            )
            lx += pill_w + 6.0

        painter.end()


class TcpFlagDistributionWidget(QWidget):
    """
    Logarithmic dot-matrix scatter plot ('TCP Flag Distribution') across time
    matching the bottom full-width panel of Photo 2.
    """

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._samples: List[TrafficSample] = []
        self.setMinimumSize(600, 185)

    def set_samples(self, samples: Sequence[TrafficSample]) -> None:
        self._samples = list(samples)[-48:]
        self.update()

    @staticmethod
    def _val_to_log_ratio(val: float) -> float:
        """Map value in [0, 100_000] to normalized height [0.0, 1.0] on log10 scale."""
        if val <= 0.0:
            return 0.0
        # 8 decades: 0.01 (-2) to 100k (+5), plus 0 at bottom
        log_v = math.log10(max(0.005, min(100_000.0, val)))
        # Map [-2.3, 5.0] -> [0.06, 1.0]
        return min(1.0, max(0.04, (log_v + 2.3) / 7.3))

    def paintEvent(self, event) -> None:  # type: ignore[override]
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)

        w = float(self.width())
        h = float(self.height())
        left_pad = 44.0
        right_pad = 14.0
        top_pad = 24.0
        bottom_pad = 40.0
        plot_w = max(120.0, w - left_pad - right_pad)
        plot_h = max(70.0, h - top_pad - bottom_pad)

        # Title
        painter.setPen(QColor("#94A3B8"))
        painter.setFont(QFont("Segoe UI", 8, QFont.Weight.Bold))
        painter.drawText(QRectF(12.0, 4.0, 14.0, 16.0), Qt.AlignmentFlag.AlignLeft, "▼")
        painter.setPen(QColor("#F1F5F9"))
        painter.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        painter.drawText(
            QRectF(26.0, 3.0, 260.0, 16.0),
            Qt.AlignmentFlag.AlignLeft,
            "TCP Flag Distribution",
        )

        # Log Y-axis grid & labels
        y_ticks = ["100 k", "10 k", "1 k", "100", "10", "1", "0.1", "0.01", "0"]
        n_rows = len(y_ticks) - 1
        painter.setFont(QFont("Segoe UI", 7))
        for idx, lbl in enumerate(y_ticks):
            gy = top_pad + (idx / n_rows) * plot_h
            painter.setPen(QPen(QColor("#20242E"), 1.0))
            painter.drawLine(QPointF(left_pad, gy), QPointF(left_pad + plot_w, gy))
            painter.setPen(QColor("#64748B"))
            painter.drawText(
                QRectF(2.0, gy - 6.0, left_pad - 6.0, 12.0),
                Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
                lbl,
            )

        # Plot multi-series scatter markers
        if self._samples:
            n = len(self._samples)
            for s_idx, sample in enumerate(self._samples):
                px = left_pad + (s_idx / max(1, n - 1)) * plot_w
                for flag_name, col_hex, shape in TCP_FLAG_SERIES:
                    val = sample.tcp_flags.get(flag_name, 0.0)
                    if val <= 0.0:
                        continue
                    # Deterministic micro-jitter per series & index for authentic scatter look
                    jitter = math.sin(s_idx * 1.7 + len(flag_name)) * 0.018
                    ratio = min(0.98, max(0.03, self._val_to_log_ratio(val) + jitter))
                    py = top_pad + plot_h - ratio * plot_h

                    painter.setPen(Qt.PenStyle.NoPen)
                    painter.setBrush(QColor(col_hex))
                    r = 2.4
                    if shape == "circle":
                        painter.drawEllipse(QPointF(px, py), r, r)
                    elif shape == "diamond":
                        poly = QPolygonF(
                            [
                                QPointF(px, py - r * 1.2),
                                QPointF(px + r * 1.2, py),
                                QPointF(px, py + r * 1.2),
                                QPointF(px - r * 1.2, py),
                            ]
                        )
                        painter.drawPolygon(poly)
                    elif shape == "triangle":
                        poly = QPolygonF(
                            [
                                QPointF(px, py - r * 1.2),
                                QPointF(px + r * 1.2, py + r),
                                QPointF(px - r * 1.2, py + r),
                            ]
                        )
                        painter.drawPolygon(poly)
                    else:
                        painter.drawRect(QRectF(px - r, py - r, r * 2.0, r * 2.0))

            # Time labels along X-axis
            step = max(1, (n - 1) // 10)
            painter.setPen(QColor("#64748B"))
            painter.setFont(QFont("Segoe UI", 7))
            for i in range(0, n, step):
                tx = left_pad + (i / max(1, n - 1)) * plot_w
                painter.drawText(
                    QRectF(tx - 20.0, top_pad + plot_h + 2.0, 40.0, 12.0),
                    Qt.AlignmentFlag.AlignCenter,
                    self._samples[i].timestamp[:5],
                )

        # Bottom TCP Flag Legend Strip
        lx = left_pad
        ly = h - 19.0
        painter.setFont(QFont("Segoe UI", 7, QFont.Weight.DemiBold))
        for flag_name, col_hex, _ in TCP_FLAG_SERIES:
            pill_w = max(46.0, len(flag_name) * 5.6 + 20.0)
            if lx + pill_w > w - right_pad:
                break
            r_pill = QRectF(lx, ly, pill_w, 15.0)
            painter.setPen(QPen(QColor("#2A2F3A"), 1.0))
            painter.setBrush(QColor("#161922"))
            painter.drawRoundedRect(r_pill, 3.0, 3.0)

            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor(col_hex))
            painter.drawEllipse(QPointF(lx + 8.0, ly + 7.5), 3.0, 3.0)

            painter.setPen(QColor("#CBD5E1"))
            painter.drawText(
                QRectF(lx + 14.0, ly, pill_w - 16.0, 15.0),
                Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                flag_name,
            )
            lx += pill_w + 5.0

        painter.end()


class TimelineScrubberSlider(QSlider):
    """Horizontal timeline scrubber with vertical ruler tick marks matching Photo 1."""

    def paintEvent(self, event) -> None:  # type: ignore[override]
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        w = float(self.width())
        h = float(self.height())
        cy = h * 0.5
        pad = 10.0
        usable_w = max(40.0, w - pad * 2.0)

        ticks = 28
        for i in range(ticks + 1):
            tx = pad + (i / ticks) * usable_w
            major = (i % 5 == 0)
            th = 5.0 if major else 3.0
            col = QColor("#64748B") if major else QColor("#334155")
            painter.setPen(QPen(col, 1.0))
            painter.drawLine(QPointF(tx, cy - th), QPointF(tx, cy + th))
        painter.end()
        super().paintEvent(event)

