import sys
import scanner
import ai_update
from PyQt5.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QWidget, QInputDialog, QMessageBox
from PyQt5.QtWebEngineWidgets import QWebEngineView
from PyQt5.QtCore import QUrl

class BugBountyDashboard(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("BugBounty Futurist Hacker Dashboard")
        self.setGeometry(100, 100, 1200, 800)
        self.initUI()

    def initUI(self):
        central_widget = QWidget()
        layout = QVBoxLayout()
        self.webview = QWebEngineView()
        self.webview.setHtml(self.dashboard_html())
        self.webview.page().urlChanged.connect(self.handle_url_change)
        layout.addWidget(self.webview)
        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)

    def dashboard_html(self):
        # Bootstrap + Futurist Hacker Theme
        return '''
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
            <style>
                body { background: #0f2027; color: #39ff14; font-family: 'Fira Mono', monospace; }
                .navbar { background: #232526; }
                .card { background: #232526; border: 1px solid #39ff14; }
                .futurist-glow { text-shadow: 0 0 8px #39ff14, 0 0 16px #39ff14; }
            </style>
            <title>BugBounty Dashboard</title>
        </head>
        <body>
            <nav class="navbar navbar-dark">
                <span class="navbar-brand mb-0 h1 futurist-glow">BugBounty Futurist Hacker Dashboard</span>
            </nav>
            <div class="container mt-4">
                <div class="row">
                    <div class="col-md-3">
                        <div class="card mb-4">
                            <div class="card-body">
                                <h5 class="card-title futurist-glow">Vulnerability Scanner</h5>
                                <p class="card-text">Run automated bug bounty tests on your targets.</p>
                                <a href="action:startscan" class="btn btn-outline-success">Start Scan</a>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card mb-4">
                            <div class="card-body">
                                <h5 class="card-title futurist-glow">AI Updates</h5>
                                <p class="card-text">Fetch latest vulnerabilities using AI and web search.</p>
                                <a href="action:aiupdate" class="btn btn-outline-info">Update Now</a>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card mb-4">
                            <div class="card-body">
                                <h5 class="card-title futurist-glow">Reports</h5>
                                <p class="card-text">View scan results and vulnerability reports.</p>
                                <a href="action:reports" class="btn btn-outline-warning">View Reports</a>
                                <a href="action:export" class="btn btn-outline-secondary mt-2">Export Latest</a>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card mb-4">
                            <div class="card-body">
                                <h5 class="card-title futurist-glow">AI Summary</h5>
                                <p class="card-text">Summarize last scan and get next steps with AI.</p>
                                <a href="action:aisummary" class="btn btn-outline-primary">AI Summary</a>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </body>
        </html>
        '''

    def handle_url_change(self, url: QUrl):
        url_str = url.toString()
        if url_str.startswith('action:startscan'):
            self.start_scan()
        elif url_str.startswith('action:aiupdate'):
            self.ai_update()
        elif url_str.startswith('action:reports'):
            self.show_reports()
        elif url_str.startswith('action:export'):
            self.export_report()
        elif url_str.startswith('action:aisummary'):
            self.ai_summary()
        else:
            pass
        self.webview.setHtml(self.dashboard_html())

    def start_scan(self):
        target_url, ok = QInputDialog.getText(self, "Start Scan", "Enter target URL:")
        if ok and target_url:
            results, report_file, _ = scanner.run_scan(target_url)
            msg = "\n".join(results)
            if report_file:
                msg += f"\n\nReport saved: {report_file}"
            QMessageBox.information(self, "Scan Result", msg)

    def export_report(self):
        report_file = scanner.export_latest_report()
        if report_file:
            QMessageBox.information(self, "Export Report", f"Latest report: {report_file}")
        else:
            QMessageBox.warning(self, "Export Report", "No reports found.")

    def ai_summary(self):
        api_key, ok = QInputDialog.getText(self, "OpenAI API Key", "Enter your OpenAI API key:")
        if not ok or not api_key:
            return
        report_file = scanner.export_latest_report()
        if not report_file:
            QMessageBox.warning(self, "AI Summary", "No reports found to summarize.")
            return
        with open(report_file, 'r', encoding='utf-8') as f:
            findings = [line.strip() for line in f if line.strip() and not line.startswith('Scan results for')]
        _, _, ai_summary = scanner.run_scan('N/A', save_report=False, ai_summary=True, openai_api_key=api_key)
        if ai_summary:
            QMessageBox.information(self, "AI Summary", ai_summary)
        else:
            QMessageBox.warning(self, "AI Summary", "AI summary could not be generated.")

    def ai_update(self):
        vulns = ai_update.fetch_latest_vulnerabilities()
        msg = "\n".join(vulns) if vulns else "No new vulnerabilities found."
        QMessageBox.information(self, "AI Update", msg)

    def show_reports(self):
        report_file = scanner.export_latest_report()
        if report_file:
            with open(report_file, 'r', encoding='utf-8') as f:
                report = f.read()
            QMessageBox.information(self, "Latest Report", report)
        else:
            QMessageBox.information(self, "Reports", "No reports found.")

def main():
    app = QApplication(sys.argv)
    window = BugBountyDashboard()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
