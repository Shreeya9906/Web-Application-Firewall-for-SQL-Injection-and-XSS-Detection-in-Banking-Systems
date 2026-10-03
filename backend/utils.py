from flask import jsonify

def success_response(data=None, message="Success", status_code=200):
    response = {"success": True, "message": message}
    if data is not None:
        response.update(data)
    return jsonify(response), status_code

def error_response(message="An error occurred", status_code=400):
    return jsonify({"success": False, "message": message}), status_code
