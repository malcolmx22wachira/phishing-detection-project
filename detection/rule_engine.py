def levenshtein(a, b):

    rows = len(a) + 1
    cols = len(b) + 1

    matrix = [[0 for _ in range(cols)] for _ in range(rows)]

    for i in range(rows):
        matrix[i][0] = i

    for j in range(cols):
        matrix[0][j] = j

    for i in range(1, rows):
        for j in range(1, cols):

            cost = 0 if a[i - 1] == b[j - 1] else 1

            matrix[i][j] = min(
                matrix[i - 1][j] + 1,
                matrix[i][j - 1] + 1,
                matrix[i - 1][j - 1] + cost
            )

    return matrix[-1][-1]


class RuleEngine:

    def analyse(self, features):

        score = 0
        triggered = []

        # Rule 1: Long URL
        if features["length"] > 75:
            score += 1
            triggered.append("Long URL")

        # Rule 2: Excessive special characters
        if features["special_chars"] > 3:
            score += 1
            triggered.append("Excessive Special Characters")

        # Rule 3: Too many subdomains
        if features["subdomains"] > 3:
            score += 1
            triggered.append("Too Many Subdomains")

        # Rule 4: No HTTPS
        if not features["https"]:
            score += 1
            triggered.append("No HTTPS")

        # Rule 5: Suspicious keywords
        if features["keywords"]:
            score += 1
            triggered.append("Suspicious Keywords")

        # Rule 6: Domain similarity
        distance = levenshtein(
            features["domain"],
            "instagram.com"
        )

        if distance < 3:
            score += 2
            triggered.append("Domain Similarity To Instagram")

        verdict = "PHISHING" if score >= 2 else "LEGITIMATE"

        return {
            "verdict": verdict,
            "score": score,
            "triggered": triggered
        }