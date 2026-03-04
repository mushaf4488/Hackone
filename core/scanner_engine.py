from utils.logger import logger
from .recon import Recon
from .crawler import Crawler
from .ssl_analyzer import SSLAnalyzer
from vulnerabilities.sqli import SQLInjectionPlugin
from vulnerabilities.xss import XSSPlugin
from vulnerabilities.misconfiguration import MisconfigurationPlugin
from vulnerabilities.exposed_database import ExposedDatabasePlugin

import concurrent.futures

class ScannerEngine:
    def __init__(self, target_url, config, controller=None):
        self.target_url = target_url
        self.config = config
        self.findings = []
        self.controller = controller

    def start_scan(self, status_callback=None):
        def emit_status(msg, process_name=None, status=None, result_data=None, module_id=None):
            if self.controller:
                self.controller.check(module_id)
            if status_callback:
                import inspect
                sig = inspect.signature(status_callback)
                if len(sig.parameters) >= 3:
                    status_callback(msg, {'name': process_name, 'status': status} if process_name else None, result_data)
                elif len(sig.parameters) > 1:
                    status_callback(msg, {'name': process_name, 'status': status} if process_name else None)
                else:
                    status_callback(msg)
            logger.info(msg)

        emit_status(f"Starting scatter-gather scan for {self.target_url}")
        
        recon_results = {}
        discovered_urls = []
        ssl_results = {}
        
        def run_recon():
            emit_status("Phase: Reconnaissance", "Reconnaissance", "running", module_id="recon")
            recon = Recon(self.target_url, self.config)
            res = recon.run(status_callback=lambda msg: emit_status(msg, "Reconnaissance", "running", module_id="recon"))
            emit_status("Reconnaissance completed.", "Reconnaissance", "completed", result_data={"type": "recon", "title": "Recon Details", "data": res}, module_id="recon")
            return ('recon', res)

        def run_crawler():
            emit_status("Phase: Crawling", "Crawling", "running", module_id="crawl")
            crawler = Crawler(self.target_url, self.config)
            urls = crawler.crawl(status_callback=lambda msg: emit_status(msg, "Crawling", "running", module_id="crawl"))
            emit_status(f"Crawling completed. Found {len(urls)} URLs.", "Crawling", "completed", result_data={"type": "crawl", "title": "Discovered URLs", "data": urls}, module_id="crawl")
            return ('crawl', urls)

        def run_ssl():
            emit_status("Phase: SSL Analysis", "SSL Analysis", "running", module_id="ssl")
            ssl_analyzer = SSLAnalyzer(self.target_url)
            ssl = ssl_analyzer.analyze()
            emit_status("SSL Analysis completed.", "SSL Analysis", "completed", result_data={"type": "ssl", "title": "SSL Analysis", "data": ssl}, module_id="ssl")
            return ('ssl', ssl)
            
        def run_plugin(plugin_class):
            plugin_name = plugin_class.__name__.replace("Plugin", "")
            emit_status(f"Running {plugin_name} scan...", plugin_name, "running", module_id="vuln")
            plugin = plugin_class(self.target_url, self.config)
            # In a real scenario, pass self.controller to plugin
            plugin_findings = plugin.scan()
            emit_status(f"{plugin_name} scan finished. Found {len(plugin_findings)} issues.", plugin_name, "completed", result_data={"type": "vuln", "plugin": plugin_name, "title": f"{plugin_name} Findings", "data": plugin_findings}, module_id="vuln")
            return ('plugin', plugin_findings)

        plugins = [
            SQLInjectionPlugin,
            XSSPlugin,
            MisconfigurationPlugin,
            ExposedDatabasePlugin
        ]

        tasks = [run_recon, run_crawler, run_ssl]
        for p in plugins:
            tasks.append((run_plugin, p))

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            if self.controller:
                self.controller.check()

            future_to_task = {}
            for task in tasks:
                if isinstance(task, tuple):
                    fut = executor.submit(task[0], task[1])
                else:
                    fut = executor.submit(task)
                future_to_task[fut] = task

            # Collect results as they complete
            for future in concurrent.futures.as_completed(future_to_task):
                if self.controller:
                    self.controller.check()
                try:
                    task_type, res = future.result()
                    if task_type == 'recon': recon_results = res
                    elif task_type == 'crawl': discovered_urls = res
                    elif task_type == 'ssl': ssl_results = res
                    elif task_type == 'plugin': self.findings.extend(res)
                except Exception as exc:
                    logger.error(f"Task generated an exception: {exc}")

        emit_status("Scan completed.", "Vulnerability Detection", "completed")
        return {
            "target": self.target_url,
            "recon": recon_results,
            "ssl": ssl_results,
            "findings": self.findings,
            "urls": discovered_urls
        }
