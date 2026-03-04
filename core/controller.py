import threading

class ScanAbortedError(Exception):
    pass

class ScanController:
    def __init__(self):
        self.global_stop_event = threading.Event()
        
        # State map for individual modules
        self.modules = {
            'recon': {'pause': threading.Event(), 'stop': threading.Event()},
            'crawl': {'pause': threading.Event(), 'stop': threading.Event()},
            'ssl': {'pause': threading.Event(), 'stop': threading.Event()},
            'vuln': {'pause': threading.Event(), 'stop': threading.Event()}
        }
        for m in self.modules.values():
            m['pause'].set() # set = can run

    def pause(self, module_id=None):
        if module_id and module_id in self.modules:
            self.modules[module_id]['pause'].clear()
        else:
            # Pause all
            for m in self.modules.values():
                m['pause'].clear()

    def resume(self, module_id=None):
        if module_id and module_id in self.modules:
            self.modules[module_id]['pause'].set()
        else:
            # Resume all
            for m in self.modules.values():
                m['pause'].set()

    def stop(self, module_id=None):
        if module_id and module_id in self.modules:
            self.modules[module_id]['stop'].set()
            self.modules[module_id]['pause'].set() # Unblock if paused
        else:
            # Global stop
            self.global_stop_event.set()
            for m in self.modules.values():
                m['stop'].set()
                m['pause'].set()

    def check(self, module_id=None):
        if self.global_stop_event.is_set():
            raise ScanAbortedError("Global scan was stopped.")
            
        if module_id and module_id in self.modules:
            if self.modules[module_id]['stop'].is_set():
                raise ScanAbortedError(f"Module {module_id} aborted.")
            
            # Block while paused
            self.modules[module_id]['pause'].wait()
            
            # Check if stopped while paused
            if self.modules[module_id]['stop'].is_set():
                raise ScanAbortedError(f"Module {module_id} aborted.")
