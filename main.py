#!/usr/bin/env python3
"""main.py - SAN Platform. IPC via console message interception."""
import sys, json, re
from pathlib import Path

APP_DIR = Path.home() / ".san-platform"
APP_DIR.mkdir(parents=True, exist_ok=True)

if hasattr(sys, '_MEIPASS'):
    sys.path.insert(0, sys._MEIPASS)
sys.path.insert(0, str(Path(__file__).parent))

from PyQt5.QtCore import Qt, QUrl, QCoreApplication, QTimer
from PyQt5.QtWidgets import QApplication, QMainWindow, QSplashScreen
from PyQt5.QtGui import QFont, QColor, QPixmap, QPainter
from PyQt5.QtWebEngineWidgets import QWebEngineView, QWebEngineSettings
from PyQt5.QtWebEngineWidgets import QWebEnginePage

SRC_DIR = Path(getattr(sys, '_MEIPASS', Path(__file__).parent)) / "src"


class BridgePage(QWebEnginePage):
    """
    Intercepts console.log messages of the form:
        __bridge__:{"id":1,"method":"login","args":["admin","pass"]}
    Executes the bridge method and calls back via runJavaScript.
    """
    _MARKER = "__bridge__:"

    def __init__(self, bridge, parent=None):
        super().__init__(parent)
        self._bridge = bridge

    def javaScriptConsoleMessage(self, level, message, line, source):
        if not message.startswith(self._MARKER):
            # Forward non-bridge messages to terminal
            if message and not message.startswith(self._MARKER):
                print(f"js: {message}")
            return
        try:
            payload = json.loads(message[len(self._MARKER):])
            call_id = payload["id"]
            method  = payload["method"]
            args    = payload.get("args", [])
        except Exception as e:
            print(f"[SAN] Bridge parse error: {e}")
            return

        # Execute bridge method
        try:
            fn = getattr(self._bridge, method, None)
            if fn is None:
                result = json.dumps({"ok": False, "error": f"No method: {method}"})
            else:
                result = fn(*args)
                if result is None:
                    result = json.dumps({"ok": True})
        except Exception as e:
            import traceback
            result = json.dumps({"ok": False, "error": str(e), "trace": traceback.format_exc()})

        # Deliver result back to JS
        safe = result.replace("\\", "\\\\").replace("`", "\\`").replace("${", "\\${")
        js = f"window.__bridgeReply({call_id}, `{safe}`);"
        QTimer.singleShot(0, lambda: self.runJavaScript(js))


class MainWindow(QMainWindow):
    def __init__(self, bridge):
        super().__init__()
        self.setWindowTitle("SAN Management Platform")
        self.setMinimumSize(1280, 800)
        self.resize(1440, 900)

        self.view = QWebEngineView()

        # Use custom page that intercepts console messages
        self._page = BridgePage(bridge, self)
        self.view.setPage(self._page)

        s = self.view.settings()
        s.setAttribute(QWebEngineSettings.JavascriptEnabled, True)
        s.setAttribute(QWebEngineSettings.LocalContentCanAccessRemoteUrls, True)
        s.setAttribute(QWebEngineSettings.ScrollAnimatorEnabled, True)

        html  = (SRC_DIR / "app.html").read_text(encoding="utf-8")
        burl  = QUrl.fromLocalFile(str(SRC_DIR / "x"))
        self._page.setHtml(html, burl)
        print(f"[SAN] Page loaded via setHtml")

        self.setCentralWidget(self.view)


def _make_splash():
    pix = QPixmap(420, 180)
    pix.fill(QColor("#0d0f14"))
    p = QPainter(pix)
    from PyQt5.QtCore import QRect
    p.setPen(QColor("#3b7eff"))
    p.setFont(QFont("Segoe UI", 20, QFont.Bold))
    p.drawText(QRect(0, 40, 420, 60), Qt.AlignCenter, "SAN Platform")
    p.setPen(QColor("#6b7899"))
    p.setFont(QFont("Segoe UI", 10))
    p.drawText(QRect(0, 110, 420, 30), Qt.AlignCenter, "Starting...")
    p.end()
    return QSplashScreen(pix)


def main():
    QCoreApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QCoreApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

    app = QApplication(sys.argv)
    app.setApplicationName("SAN Management Platform")
    app.setApplicationVersion("5.0")
    app.setFont(QFont("Segoe UI", 10))

    splash = _make_splash()
    splash.show()
    app.processEvents()

    if "--reset-db" in sys.argv:
        import shutil
        if APP_DIR.exists():
            shutil.rmtree(APP_DIR)
            APP_DIR.mkdir(parents=True, exist_ok=True)
        print("[SAN] Database reset")

    from db.database import init_db, DB_PATH
    print(f"[SAN] Database: {DB_PATH}")
    init_db()
    print("[SAN] Database ready")
    app.processEvents()

    from bridge import Bridge
    from workers.poller import MdsPoller

    bridge = Bridge()
    poller = MdsPoller(on_update=lambda: None)
    poller.start()

    win = MainWindow(bridge)
    splash.finish(win)
    win.show()

    ret = app.exec_()
    poller.stop()
    return ret


if __name__ == "__main__":
    sys.exit(main())
