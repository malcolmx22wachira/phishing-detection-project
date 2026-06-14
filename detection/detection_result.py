class DetectionResult:

    def __init__(self, verdict, triggered, score):
        self.verdict = verdict
        self.triggered = triggered
        self.score = score

    def explain(self):
        return f"{self.verdict} | Score: {self.score} | Rules: {self.triggered}"