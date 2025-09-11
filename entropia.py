import os
import time
import psutil
import logging
import threading
import math
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# =============================
# CONFIGURAÇÕES
# =============================
MONITOR_DIR = "C:/Users/Public"  # pasta alvo (alterar para ambiente corporativo)
LOG_FILE = "ransomware_detector.log"
THRESHOLD_CHANGES = 20  # nº de arquivos modificados em pouco tempo
TIME_WINDOW = 10  # janela de tempo (segundos) para medir alterações
WHITELIST_PROCESSES = {'Teams.exe', 'ms-teams.exe', 'Zoom.exe', 'Skype.exe', 'Webex.exe', 'AnyDesk.exe', 'TeamViewer.exe'}  # processos de compartilhamento de tela

# =============================
# LOGGING
# =============================
logging.basicConfig(filename=LOG_FILE, level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# =============================
# FUNÇÕES DE APOIO
# =============================
def calc_entropy(file_path):
    """ Calcula entropia de um arquivo (para detectar criptografia) """
    try:
        with open(file_path, "rb") as f:
            data = f.read()
        if not data:
            return 0
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        entropy = 0
        for c in freq:
            if c:
                p = c / len(data)
                entropy -= p * math.log2(p)
        return entropy
    except Exception:
        return 0

def kill_process(pid):
    """ Isola e mata processo suspeito """
    try:
        proc = psutil.Process(pid)
        if proc.name() not in WHITELIST_PROCESSES:
            logging.warning(f"[ALERTA] Encerrando processo suspeito: {proc.name()} (PID {pid})")
            proc.terminate()
        else:
            logging.info(f"[IGNORADO] Processo {proc.name()} (PID {pid}) está na lista de permissões (compartilhamento de tela)")
    except Exception as e:
        logging.error(f"Erro ao encerrar processo {pid}: {e}")

# =============================
# DETECTOR DE RANSOMWARE
# =============================
class RansomwareHandler(FileSystemEventHandler):
    def __init__(self):
        self.changes = []

    def on_modified(self, event):
        if not event.is_directory:
            self.detect(event.src_path)

    def on_created(self, event):
        if not event.is_directory:
            self.detect(event.src_path)

    def detect(self, file_path):
        now = time.time()
        self.changes = [t for t in self.changes if now - t < TIME_WINDOW]
        self.changes.append(now)

        # Verifica entropia
        entropy = calc_entropy(file_path)
        logging.info(f"Arquivo alterado: {file_path}, Entropia={entropy:.2f}")

        if entropy > 7.5:  # entropia alta indica criptografia
            logging.warning(f"[SUSPEITO] {file_path} parece criptografado (entropia={entropy:.2f})")

        # Se muitas alterações em pouco tempo -> possível ransomware
        if len(self.changes) > THRESHOLD_CHANGES:
            logging.critical("[ATAQUE DETECTADO] Atividade suspeita detectada - possível ransomware!")
            # Ação defensiva: matar processos com alta CPU/disk
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
                if proc.info['cpu_percent'] > 50:
                    kill_process(proc.info['pid'])

# =============================
# MAIN
# =============================
def start_monitoring():
    logging.info("Iniciando monitoramento anti-ransomware...")
    event_handler = RansomwareHandler()
    observer = Observer()
    observer.schedule(event_handler, MONITOR_DIR, recursive=True)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    start_monitoring()
