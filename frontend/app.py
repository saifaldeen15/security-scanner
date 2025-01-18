from flask import Flask, render_template, jsonify, request, session
import requests
import os
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Tuple
from requests.exceptions import Timeout, ConnectionError
import pymongo

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.debug = True
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'your-secret-key')
app.permanent_session_lifetime = timedelta(minutes=5)

@app.before_request
def make_session_permanent():
    session.permanent = True

MONGO_URL = os.getenv("MONGODB_URL", "mongodb://mongodb-service:27017")
mongo_client = pymongo.MongoClient(MONGO_URL)
db = mongo_client["security_scanner"]
scan_results_collection = db["scan_results"]

def store_scan_result(code: str, analysis_results: Dict[str, Any]) -> str:
    """
    Store scan results in MongoDB directly.
    Returns the inserted document ID as a string.
    """
    document = {
        "timestamp": datetime.utcnow(),
        "source_code": code,
        "static_analysis": analysis_results.get('static_analysis'),
        "dependency_analysis": analysis_results.get('dependency_analysis'),
        "ai_analysis": analysis_results.get('ai_analysis'),
        "overall_security_score": analysis_results.get('overall_security_score'),
    }
    result = scan_results_collection.insert_one(document)
    return str(result.inserted_id)

def get_recent_scans(limit: int = 10) -> list:
    """
    Retrieve recent scans from MongoDB.
    """
    docs = scan_results_collection.find().sort("timestamp", -1).limit(limit)
    return [{**doc, "_id": str(doc["_id"])} for doc in docs]

SERVICE_CONFIG = {
    'ai': {
        'url': os.getenv('AI_ANALYZER_URL', 'http://ai-analyzer:5001'),
        'weight': 0.5,
        'timeout': 30
    },
    'static': {
        'url': os.getenv('STATIC_ANALYZER_URL', 'http://static-analyzer:5003'),
        'weight': 0.2,
        'timeout': 30
    },
    'dependency': {
        'url': os.getenv('DEPENDENCY_SCANNER_URL', 'http://dependency-analyzer:5004'),
        'weight': 0.3,
        'timeout': 30
    }
}

def create_error_response(service_name: str, error: Exception) -> Dict[str, Any]:
    """Create a standardized error response for a service failure"""
    if isinstance(error, Timeout):
        message = f"{service_name} service timed out"
    elif isinstance(error, ConnectionError):
        message = f"Could not connect to {service_name} service"
    else:
        message = f"{service_name} service error: {str(error)}"

    logger.error(message)
    return {
        'error': message,
        'status': 'error',
        'issues': [],
        'summary': {'total_issues': 0}
    }

def get_default_service_response(service_type: str) -> Dict[str, Any]:
    """Get default response structure for a service"""
    defaults = {
        'static': {
            'issues': [],
            'summary': {'total_issues': 0}
        },
        'dependency': {
            'vulnerable_packages': [],
            'total_vulnerabilities': 0
        },
        'ai': {
            'findings': [],
            'risk_score': 0
        }
    }
    return defaults.get(service_type, {})

@app.route('/')
def index():
    """Render the main page"""
    stored_results = session.get('analysis_results')
    return render_template('index.html', stored_results=stored_results)

@app.route('/health')
def health_check() -> Tuple[Dict[str, Any], int]:
    """Check health status of the external analyzers only."""
    health_status = {}
    all_healthy = True

    for service_name, config in SERVICE_CONFIG.items():
        try:
            response = requests.get(f"{config['url']}/health", timeout=5)
            is_healthy = response.status_code == 200
            if not is_healthy:
                all_healthy = False
        except Exception as e:
            logger.error(f"Health check failed for {service_name}: {str(e)}")
            is_healthy = False
            all_healthy = False

        health_status[service_name] = is_healthy

    try:
        mongo_client.admin.command('ping') # Check MongoDB connection
        health_status['mongodb'] = True
    except Exception as e:
        logger.error(f"Health check failed for MongoDB: {str(e)}")
        health_status['mongodb'] = False
        all_healthy = False

    return jsonify({
        'status': 'healthy' if all_healthy else 'degraded',
        'services': health_status
    }), 200 if all_healthy else 503

@app.route('/analyze', methods=['POST'])
def analyze_code() -> Tuple[Dict[str, Any], int]:
    """Endpoint to analyze code using all three analyzers"""
    if not request.json or 'code' not in request.json:
        return jsonify({'error': 'No code provided', 'status': 'error'}), 400

    code = request.json['code']
    services_results = {}

    # Static Analysis
    try:
        static_results = perform_static_analysis(code)
        services_results['static'] = static_results
    except Exception as e:
        services_results['static'] = create_error_response('Static Analysis', e)

    # Dependency Analysis
    try:
        dependency_results = perform_dependency_analysis(code)
        services_results['dependency'] = dependency_results
    except Exception as e:
        services_results['dependency'] = create_error_response('Dependency Analysis', e)

    # AI Analysis
    try:
        ai_results = perform_ai_analysis(code)
        services_results['ai'] = ai_results
    except Exception as e:
        services_results['ai'] = create_error_response('AI Analysis', e)

    # Combine results
    combined_results = {
        'static_analysis': services_results['static'],
        'dependency_analysis': services_results['dependency'],
        'ai_analysis': services_results['ai'],
        'status': 'success' if all(not r.get('error') for r in services_results.values()) else 'partial',
        'overall_security_score': calculate_overall_security_score(
            services_results['static'],
            services_results['dependency'],
            services_results['ai']
        )
    }

    try:
        scan_id = store_scan_result(code, combined_results)
        combined_results['scan_id'] = scan_id
    except Exception as e:
        logger.error(f"Failed to store results in MongoDB: {str(e)}")

    # Store in session
    session.permanent = True
    session['analysis_results'] = combined_results

    return jsonify(combined_results), 200

def perform_static_analysis(code: str) -> Dict[str, Any]:
    """Perform static code analysis"""
    try:
        response = requests.post(
            f"{SERVICE_CONFIG['static']['url']}/analyze",
            json={'code': code},
            timeout=SERVICE_CONFIG['static']['timeout']
        )
        response.raise_for_status()
        return response.json()
    except Exception as e:
        logger.error(f"Static analysis failed: {str(e)}")
        return get_default_service_response('static')

def perform_dependency_analysis(code: str) -> Dict[str, Any]:
    """Analyze code dependencies"""
    try:
        response = requests.post(
            f"{SERVICE_CONFIG['dependency']['url']}/analyze",
            json={'code': code},
            timeout=SERVICE_CONFIG['dependency']['timeout']
        )
        response.raise_for_status()
        return response.json().get('dependency_analyzer', {})
    except Exception as e:
        logger.error(f"Dependency analysis failed: {str(e)}")
        return get_default_service_response('dependency')

def perform_ai_analysis(code: str) -> Dict[str, Any]:
    """Perform AI-based code analysis"""
    try:
        response = requests.post(
            f"{SERVICE_CONFIG['ai']['url']}/analyze",
            json={'code': code},
            timeout=SERVICE_CONFIG['ai']['timeout']
        )
        response.raise_for_status()
        return response.json()
    except Exception as e:
        logger.error(f"AI analysis failed: {str(e)}")
        return get_default_service_response('ai')

def calculate_overall_security_score(
    static_results: Dict[str, Any],
    dependency_results: Dict[str, Any],
    ai_results: Dict[str, Any]
) -> float:
    try:
        static_issues = static_results.get('static_analyzer', {}).get('summary', {}).get('total_issues', 0)
        static_score = max(0, min(100, 100 - (static_issues * 3)))

        dep_vulnerabilities = dependency_results.get('total_vulnerabilities_found', 0)
        dep_score = max(0, min(100, 100 - (dep_vulnerabilities * 5)))

        ai_risk_score = ai_results.get('data', {}).get('risk_score', 0)
        ai_score = max(0, min(100, 100 - (ai_risk_score * 8)))

        overall_score = (
            static_score * 0.2 +
            dep_score * 0.3 +
            ai_score * 0.5
        )
        return round(overall_score, 2)
    except Exception as e:
        logger.error(f"Error calculating overall score: {str(e)}")
        return 0.0

@app.route('/static-analysis')
def static_analysis_details():
    results = session.get('analysis_results', {}).get('static_analysis', {})
    return render_template(
        'analysis_details.html',
        analysis_type='Static Analysis',
        results=results,
        overall_security_score=session.get('analysis_results', {}).get('overall_security_score', 0)
    )

@app.route('/dependency-analysis')
def dependency_analysis_details():
    results = session.get('analysis_results', {}).get('dependency_analysis', {})
    return render_template(
        'analysis_details.html',
        analysis_type='Dependency Analysis',
        results=results
    )

@app.route('/ai-analysis')
def ai_analysis_details():
    results = session.get('analysis_results', {}).get('ai_analysis', {})
    return render_template(
        'analysis_details.html',
        analysis_type='AI Analysis',
        results=results
    )

@app.route('/recent-scan')
def recent_scan():
    """Get recent scans directly from MongoDB"""
    try:
        limit = request.args.get('limit', default=1, type=int)
        docs = get_recent_scans(limit)
        return jsonify(docs), 200
    except Exception as e:
        logger.error(f"Error retrieving recent scan: {str(e)}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    logger.info("Starting Security Scanner Frontend (direct MongoDB)")
    for service, config in SERVICE_CONFIG.items():
        logger.info(f"{service.title()} Service URL: {config['url']}")

    logger.info(f"MongoDB URL: {MONGO_URL}")
    app.run(host='0.0.0.0', port=5000, debug=True)
