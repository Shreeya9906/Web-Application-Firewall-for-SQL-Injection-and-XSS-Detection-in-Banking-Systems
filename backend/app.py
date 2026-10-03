from flask import Flask, request, jsonify, session
from flask_cors import CORS
from datetime import datetime
from backend.database import close_db
from backend.routes.auth_routes import auth_bp
from backend.routes.account_routes import account_bp
from backend.routes.transaction_routes import transaction_bp
from backend.routes.beneficiary_routes import beneficiary_bp
from backend.routes.security_routes import security_bp
from backend.services.waf import check_request
from backend.services.security_logger import log_security_event
from backend.services.behavior_monitor import analyze_behavior
from backend.services.email_alerts import notify_blocked_security_event
from backend.database import get_db
import os


SENSITIVE_PARAMETER_PARTS = ('password', 'token', 'secret', 'credit_card', 'authorization')


def _is_sensitive_parameter(parameter_name):
    normalized_name = parameter_name.lower()
    return any(part in normalized_name for part in SENSITIVE_PARAMETER_PARTS)

def create_app():
    app = Flask(__name__)
    
    # Configuration
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'development_secret_key_change_in_production')
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    
    # Enable CORS for local React dev server
    CORS(app, supports_credentials=True, origins=["http://localhost:5173", "http://127.0.0.1:5173"])
    
    # Register WAF Middleware
    @app.before_request
    def waf_middleware():
        if request.method == 'OPTIONS':
            return
            
        if not request.path.startswith('/api'):
            return
            
        waf_result = check_request(request)
        if waf_result.get("blocked"):
            if waf_result.get("error"):
                app.logger.error("WAF unavailable: %s", waf_result.get("model_error", "unknown error"))
                return jsonify({
                    "success": False,
                    "message": "Web Application Firewall is unavailable."
                }), 503

            param_name = waf_result.get("parameter_name", "unknown")
            raw_value = waf_result.get("request_value", "")
            logged_value = "[REDACTED]" if _is_sensitive_parameter(param_name) else raw_value
            customer_id = session.get('customer_id')
            source_ip = request.remote_addr or '127.0.0.1'
            behavior = analyze_behavior(
                get_db(), source_ip, customer_id, waf_result.get("attack_type", "Unknown")
            )
            risk_level = "CRITICAL" if behavior["behavior_detected"] else waf_result.get("risk_level", "HIGH")
            risk_score = 1.0 if behavior["behavior_detected"] else waf_result.get("risk_score")
            reason = behavior["reason"] if behavior["behavior_detected"] else waf_result.get("reason", "WAF blocked request")

            event_id = log_security_event(
                customer_id=customer_id,
                source_ip=source_ip,
                endpoint=request.path,
                http_method=request.method,
                parameter_name=param_name,
                request_value=logged_value,
                attack_type=waf_result.get("attack_type", "Unknown"),
                confidence=risk_score if risk_score is not None else waf_result.get("confidence", 1.0),
                action="BLOCK",
                reason=reason
            )
            notification_status = notify_blocked_security_event(
                get_db(),
                event_id,
                customer_id,
                waf_result.get("attack_type", "Unknown"),
                datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                risk_level,
                behavior.get("behavior_detected", False),
            )
            
            return jsonify({
                "success": False,
                "blocked": True,
                "attack_type": waf_result.get("attack_type", "Unknown"),
                "risk_level": risk_level,
                "risk_score": risk_score,
                "decision": waf_result.get("decision", "BLOCK"),
                "source": waf_result.get("source"),
                "reason": reason,
                "explanation": reason,
                "evidence": waf_result.get("evidence", []),
                "detections": waf_result.get("detections", []),
                "behavior": behavior,
                "event_id": event_id,
                "notification_status": notification_status,
                "message": "Request blocked by Web Application Firewall."
            }), 403

    # Register blueprints
    app.register_blueprint(auth_bp, url_prefix='/api')
    app.register_blueprint(account_bp, url_prefix='/api')
    app.register_blueprint(transaction_bp, url_prefix='/api')
    app.register_blueprint(beneficiary_bp, url_prefix='/api')
    app.register_blueprint(security_bp, url_prefix='/api/security')
    
    # Register teardown
    app.teardown_appcontext(close_db)
    
    @app.route('/api/waf/status', methods=['GET'])
    def waf_status():
        return jsonify({
            "enabled": True,
            "engine": "Machine Learning",
            "attack_detection": ["SQL Injection", "XSS"]
        })
    
    @app.route('/')
    def index():
        return {"status": "Banking API is running"}
        
    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True, port=5000)
