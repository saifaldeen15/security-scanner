from flask import Flask, request, jsonify
from analyzer.AI_analyzer import AIAnalyzer
from config import CONFIG

app = Flask(__name__)
ai_analyzer = AIAnalyzer(config=CONFIG)

@app.route('/analyze', methods=['POST'])
def analyze():
    """
    API endpoint to analyze provided code
    """
    try:
        data = request.get_json()
        code = data.get("code")
        if not code:
            return jsonify({"error": "No code provided"}), 400

        results = ai_analyzer.analyze_code(code)

        # Check if response was successfully formatted
        if not results:
            return jsonify({
                "status": "error",
                "message": "Failed to analyze code",
            }), 500
        return jsonify({
                "status": "success",
                "data": results,
            })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(host=CONFIG['SERVER_HOST'], port=CONFIG['SERVER_PORT'])