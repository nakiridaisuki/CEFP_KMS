from flask import jsonify
from typing import Dict

def standard_response(success=True, data=None, message="", code=200):
    if isinstance(data, Dict):
        keys = data.keys()
        if('hashed_password' in keys):
            del data['hashed_password']
        if('salt' in keys):
            del data['salt']

    return jsonify({
        "success": success,
        "data": data,
        "message": message
    }), code