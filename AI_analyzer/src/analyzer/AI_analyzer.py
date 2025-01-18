from anthropic import Anthropic
import json

from typing import Dict, Any


class AIAnalyzer:
    """
    A class that uses Claude AI to analyze code for security vulnerabilities
    """

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the AI Analyzer with configuration
        """
        self.client = Anthropic(api_key=config['ANTHROPIC_API_KEY'])
        self.model = config['AI_MODEL']



    def format_response(self, text: str) -> Dict[str, Any]:
        new = text.replace('\\n', '')
        new = new.replace('\n', '')
        new = new.replace('`', '')
        new = new.replace("[TextBlock(text='", '')
        new = new.replace("', type='text')]", '')
        new = new.replace("[N/A]", '"[N/A]"')
        new = new.replace('\"', '"')
        new = new.replace('\'', '"')
        try:
            json_data = json.loads(new)
            return json_data
        except json.JSONDecodeError as e:
            print(f"Error parsing JSON: {e}")
            return "Error parsing JSON"
        # return new


    def analyze_code(self, code: str) -> Dict[str, Any]:
        """
        Analyze provided code using Claude AI

        Args:
            code (str): Source code to analyze

        Returns:
            dict: Analysis results containing security findings
        """
        prompt = f"""
        You are an expert code security analyzer. Please perform a comprehensive security analysis of the following code.
        Analyze for these specific categories:

        1. Security Vulnerabilities:
           - Injection vulnerabilities (SQL, Command, etc.)
           - Authentication issues
           - Authorization flaws
           - Data exposure risks
           - Cryptographic problems
           - Secret management
           - Input validation issues

        2. Code Quality & Best Practices:
           - OWASP top 10 violations
           - Secure coding guidelines violations
           - Error handling practices
           - Logging security concerns
           - Documentation completeness
           - Code structure and organization

        3. Performance & Resource Management:
           - Resource leaks
           - Memory management issues
           - Concurrency problems
           - Scalability concerns
           - Database query efficiency
           - API endpoint security

        4. Compliance & Standards:
           - GDPR compliance issues
           - PCI DSS violations
           - Industry-standard security practices
           - Framework-specific security best practices

        Code to analyze:
        {code}

        YOUR RESPONSE MUST BE A SINGLE VALID JSON OBJECT FOLLOWING THIS EXACT STRUCTURE, WITH NO ADDITIONAL TEXT OR EXPLANATIONS:
        {{
            "findings": [
                {{
                    "severity": "high/medium/low",
                    "category": "security/quality/performance/compliance",
                    "issue_type": "specific type of issue",
                    "line_numbers": [affected line numbers],
                    "description": "detailed description of the issue",
                    "impact": "potential impact of this vulnerability",
                    "recommendation": "specific steps to fix the issue",
                    "references": [
                        "relevant OWASP links",
                        "security documentation links",
                        "best practice guidelines"
                    ],
                    "cwe_id": "if applicable, the CWE identifier"
                }}
            ],
            "risk_score": "numerical score from 1-10",
            "critical_issues_count": "number of critical findings",
            "scan_metadata": {{
                "framework_detected": "detected framework name",
                "language": "detected programming language",
                "libraries_analyzed": ["list of detected libraries"]
            }}
        }}
        """

        # Call Claude API for analysis
        response = self.client.messages.create(
            model=self.model,
            messages=[{
                "role": "user",
                "content": prompt
            }],
            max_tokens=4000 # the maximum number of tokens Claude can generate is 4096
        )

        # Convert response content to string
        response_text = str(response.content)

        formatted_response = self.format_response(response_text)
        return  formatted_response