from flask import Flask, render_template, Response
import threading
import time
import os


from entropia import start_monitoring, LOG_FILE  

app = Flask(__name__)

monitoring_started = False

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/start")
def start():
    global monitoring_started
    if not monitoring_started:
        thread = threading.Thread(target=start_monitoring, daemon=True)
        thread.start()
        monitoring_started = True
    return "Monitoramento iniciado!"

@app.route("/logs")
def stream_logs():
    def generate():
        last_size = 0
        while True:
            if os.path.exists(LOG_FILE):
                with open(LOG_FILE, "r") as f:
                    f.seek(last_size)
                    new_logs = f.read()
                    last_size = f.tell()
                    if new_logs:
                        yield f"data: {new_logs}\n\n"
            time.sleep(2)
    return Response(generate(), mimetype="text/event-stream")

if __name__ == "__main__":
    app.run(debug=True)
