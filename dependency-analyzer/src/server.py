#dependency-analyzer/src/server.py
from flask import Flask, request, jsonify
from analyzer.dependency_analyzer import DependencyAnalyzer


app = Flask(__name__)
dependency_analyzer = DependencyAnalyzer()

@app.route('/analyze', methods=['POST'])
def analyze_dependencies():
    """
    Endpoint to analyze code dependencies for vulnerabilities
    """
    try:
        # Get code from request
        data = request.get_json()
        code = data.get('code')

        if not code:
            return jsonify({'error': 'No code provided'}), 400
        # Analyze dependencies and vulnerabilities
        results = dependency_analyzer.analyze(code)
        return jsonify({
                "status": "success",
                "dependency_analyzer": results,
            })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5004)