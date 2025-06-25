from flask import Flask, request, make_response
import random

app = Flask(__name__)

# Configurable WAF rules (internal only)
WAF_RULES = {
    "blocks_scripts": True,
    "blocks_angle_brackets": False,
    "blocks_onerror": False,
    "blocks_svg": True,
    "blocks_javascript": True
}

@app.route("/search")
def search():
    query = request.args.get("q", "")
    
    # WAF Simulation
    blocked = False
    if WAF_RULES["blocks_scripts"] and "script" in query.lower():
        blocked = True
    if WAF_RULES["blocks_svg"] and "svg" in query.lower():
        blocked = True
    if WAF_RULES["blocks_javascript"] and "javascript:" in query.lower():
        blocked = True

    if blocked:
        return "Blocked by WAF", 403
    
    # Vulnerability check
    vulnerable = any(
        trigger in query.lower() 
        for trigger in ["alert(", "prompt(", "confirm(", "eval("]
    )
    
    response = make_response(f"""
        <html>
        <body>
            <h2>Search Results</h2>
            <div>Query: {query}</div>
            <div>Vulnerable: {vulnerable}</div>
        </body>
        </html>
    """)
    
    # Randomly rotate WAF rules to simulate learning environment
    if random.random() > 0.8:
        WAF_RULES["blocks_scripts"] = not WAF_RULES["blocks_scripts"]
    if random.random() > 0.8:
        WAF_RULES["blocks_svg"] = not WAF_RULES["blocks_svg"]
    
    return response

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
