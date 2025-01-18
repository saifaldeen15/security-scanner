import tempfile
import json
from pylint import lint
import pyflakes.api
import bandit.core.manager
from bandit.core import config
from typing import Dict, Any, List
import io
from contextlib import redirect_stdout

class StaticAnalyzer:
    """
    A class that performs static analysis on Python code using multiple tools:
    - Pylint: For code quality and style checking
    - Pyflakes: For quick syntax and error checking
    - Bandit: For security vulnerability scanning
    """
    def __init__(self):
        """Initialize the StaticAnalyzer with default configurations"""
        self.pylint_opts = [
            '--output-format=json',
            '--disable=C',  # Disable convention messages
            '--enable=W,E,F,R'  # Enable warnings, errors, fatal, refactor messages
        ]
        self.bandit_conf = config.BanditConfig()

    def parse_pylint_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse Pylint JSON output and extract relevant information"""
        try:
            issues = json.loads(output)
            return [{
                'type': issue['type'],
                'line': issue['line'],
                'message': issue['message'],
                'symbol': issue['symbol'],
                'severity': 'HIGH' if issue['type'] in ['error', 'fatal'] else 'MEDIUM'
            } for issue in issues if issue['type'] in ['error', 'warning', 'fatal']]
        except Exception as e:
            return [{'type': 'error', 'message': f'Failed to parse Pylint output: {str(e)}'}]

    def run_pylint(self, code: str) -> List[Dict[str, Any]]:
        """Run Pylint analysis on the provided code"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py') as temp_file:
            temp_file.write(code)
            temp_file.flush()

            output = io.StringIO()
            with redirect_stdout(output):
                lint.Run([temp_file.name] + self.pylint_opts, exit=False)

            return self.parse_pylint_output(output.getvalue())

    def run_pyflakes(self, code: str) -> List[Dict[str, Any]]:
        """Run Pyflakes analysis on the provided code"""
        class JSONReporter:
            def __init__(self):
                self.issues = []

            def unexpectedError(self, msg):
                self.issues.append({
                    'type': 'error',
                    'message': str(msg),
                    'severity': 'HIGH'
                })

            def syntaxError(self, msg, lineno):
                self.issues.append({
                    'type': 'syntax-error',
                    'line': lineno,
                    'message': str(msg),
                    'severity': 'HIGH'
                })

            def flake(self, message):
                self.issues.append({
                    'type': 'warning',
                    'line': message.lineno,
                    'message': str(message.message),
                    'severity': 'MEDIUM'
                })

        with tempfile.NamedTemporaryFile(mode='w', suffix='.py') as temp_file:
            temp_file.write(code)
            temp_file.flush()

            reporter = JSONReporter()
            pyflakes.api.checkPath(temp_file.name, reporter)
            return reporter.issues

    def run_bandit(self, code: str) -> List[Dict[str, Any]]:
        """Run Bandit security analysis on the provided code"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py') as temp_file:
            temp_file.write(code)
            temp_file.flush()
            b_mgr = bandit.core.manager.BanditManager(self.bandit_conf, 'file')
            b_mgr.discover_files([temp_file.name])
            b_mgr.run_tests()
            issues = []
            for issue in b_mgr.get_issue_list():
                issues.append({
                    'type': 'security',
                    'line': issue.lineno,
                    'message': issue.text,
                    'severity': issue.severity,
                    'confidence': issue.confidence,
                    'test_id': issue.test_id
                })
            return issues

    def analyze(self, code: str) -> Dict[str, Any]:
        """Perform complete static analysis using all tools"""
        try:
            pylint_results = self.run_pylint(code)
            pyflakes_results = self.run_pyflakes(code)
            bandit_results = self.run_bandit(code)

            results = {
                "status": "success",
                "issues": {
                    "code_quality": pylint_results,
                    "syntax": pyflakes_results,
                    "security": bandit_results
                },
                "summary": {
                    "total_issues": len(pylint_results) + len(pyflakes_results) + len(bandit_results),
                    "security_issues": len(bandit_results),
                    "code_quality_issues": len(pylint_results),
                    "syntax_issues": len(pyflakes_results)
                }
            }
            #save in a folder
            with open('static_analysis_results.json', 'w') as f:
                json.dump(results, f, indent=4)
        except Exception as e:
            results = {
                "status": "error",
                "message": str(e)
            }
        return results