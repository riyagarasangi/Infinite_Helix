import datetime

class EventLogger:
    def __init__(self):
        self.logs = []
        self.max_logs = 100

    def log(self, event_type, message, severity="info", module="system", stage="detection"):
        """
        Log an event.
        severity: info, success, warning, danger
        module: system, sql, network, iot, ml, iam
        stage: attack, detection, analysis, defense, blocked
        """
        event = {
            "timestamp": datetime.datetime.now().strftime("%H:%M:%S"),
            "type": event_type,
            "message": message,
            "severity": severity,
            "module": module,
            "stage": stage
        }
        self.logs.insert(0, event)
        if len(self.logs) > self.max_logs:
            self.logs.pop()
        return event

    def get_logs(self):
        return self.logs

    def clear(self):
        self.logs = []

# Global instance
logger = EventLogger()
