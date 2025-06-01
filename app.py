from flask import Flask, request, jsonify, abort
import os, subprocess, json

app = Flask(__name__)
API_KEY = os.environ.get("SCAN_API_KEY")

def run_nmap(target, ports, flags):
    cmd = ["nmap", *flags.split(), "-p", ports, "-oJ", "-", target]
    result = subprocess.run(cmd, capture_output=True, text=True)

    stdout = result.stdout
    # find the first “{” so we only parse the JSON part
    idx = stdout.find("{")
    if idx == -1:
        # nothing looked like JSON, so fail loudly
        raise RuntimeError(
            "Nmap did not produce JSON:\n"
            + stdout
            + "\nstderr:\n"
            + result.stderr
        )
    json_text = stdout[idx:]
    return json.loads(json_text)

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
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
