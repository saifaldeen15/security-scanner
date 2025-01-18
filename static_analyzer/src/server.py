from flask import Flask, request, jsonify
from analyzer.static_analyzer import StaticAnalyzer

app = Flask(__name__)
analyzer = StaticAnalyzer()

@app.route('/analyze', methods=['POST'])
def analyze_code():
    try:
        data = request.get_json()
        if not data or 'code' not in data:
            return jsonify({"error": "No code provided"}), 400

        results = analyzer.analyze(data['code'])
        if not results:
            return jsonify({
                "status": "error",
                "error": "No results found"}), 400
        return jsonify({
            "status": "success",
            "static_analyzer": results,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500



if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5003, debug=True)