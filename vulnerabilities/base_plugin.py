from abc import ABC, abstractmethod

class BasePlugin(ABC):
    def __init__(self, target_url, config):
        self.target_url = target_url
        self.config = config
        self.results = []

    @abstractmethod
    def scan(self):
        """
        Execute the vulnerability scan.
        Should return a list of findings.
        """
        pass

    def add_finding(self, finding):
        self.results.append(finding)
