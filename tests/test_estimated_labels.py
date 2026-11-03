"""P3: protocol/port/flag charts must disclose estimated telemetry when Npcap is absent."""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

pytest.importorskip("PySide6")

from PySide6.QtWidgets import QApplication  # noqa: E402

from src.gui.main_window import MainWindow  # noqa: E402
from src.gui.widgets.cyber_charts import (  # noqa: E402
    HorizontalBreakdownBarWidget,
    TcpFlagDistributionWidget,
)


@pytest.fixture(scope="module")
def qapp():
    return QApplication.instance() or QApplication([])


def test_suffix_estimated_mode():
    assert "Estimated" in MainWindow.breakdown_suffix("ESTIMATED_NIC", True)
    assert "Local OS Sockets" in MainWindow.breakdown_suffix("ESTIMATED_NIC", True)


def test_suffix_demo_mode():
    assert "Demo" in MainWindow.breakdown_suffix("DEMO_SYNTHETIC", True)


def test_suffix_live_capture_mode():
    suffix = MainWindow.breakdown_suffix("LIVE_PCAP", False)
    assert "Live" in suffix
    assert "Estimated" not in suffix


def test_widget_titles_update(qapp):
    bar = HorizontalBreakdownBarWidget("Protocol Breakdown")
    bar.set_title("Protocol Breakdown (Estimated — Local OS Sockets)")
    assert "Estimated" in bar.title

    flags = TcpFlagDistributionWidget()
    assert flags.title == "TCP Flag Distribution"
    flags.set_title("TCP Flag Distribution (Estimated — Local OS Sockets)")
    assert "Estimated" in flags.title

