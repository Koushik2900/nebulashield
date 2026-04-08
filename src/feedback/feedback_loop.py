import logging

class FeedbackLoop:
    def __init__(self):
        # Set up the logging configuration
        logging.basicConfig(filename='security_decisions.log', level=logging.INFO)

    def log_decision(self, decision, details):
        """Logs a security decision with associated details."""
        logging.info(f'Decision: {decision}, Details: {details}')

    def collect_feedback(self, analyst_feedback):
        """Collects feedback from analysts on security decisions."""
        # Here, we could store feedback in a database or a file
        # For now, we will just log it.
        logging.info(f'Analyst Feedback: {analyst_feedback}')