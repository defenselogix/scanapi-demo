from flask import Flask, request, jsonify, abort
import os, subprocess, json

app = Flask(__name__)
API_KEY = os.environ.get("SCAN_API_KEY")

def run_nmap(target, ports, flags):
    # “-oJ-” is fine even if Nmap doesn’t produce JSON; we’ll still capture stdout/stderr as text
    cmd = ["nmap", *flags.split(), "-p", ports, "-oJ-", target]
    result = subprocess.run(cmd, capture_output=True, text=True)

    # Concatenate stdout/stderr so the caller can see everything Nmap printed
    raw_text = result.stdout
    if result.stderr:
        raw_text += "\nstderr:\n" + result.stderr

    # Return a dict – jsonify() will wrap this in {"raw": "..."} in the response
    return {"raw": raw_text}

@app.route("/scan", methods=["POST"])
def scan():
    key = request.headers.get("x-api-key")
    if API_KEY is None or key != API_KEY:
        abort(401)

    data = request.get_json()
    target = data.get("target")
    ports  = data.get("ports", "1-65535")
    flags  = data.get("flags", "-sS -Pn -T4")

    try:
        output = run_nmap(target, ports, flags)
        return jsonify(output)
    except Exception as e:
        # If something else inside run_nmap explodes, we still return a 500 with the Python exception message
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
