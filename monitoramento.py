import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time
import logging
import os

# Configura o logging
logging.basicConfig(
    level=logging.DEBUG,  # Alterado para DEBUG para mais detalhes
    filename="ransomware.log",
    format="%(asctime)s - %(levelname)s - %(message)s",
    encoding="utf-8"
)

class FileMonitor(FileSystemEventHandler):
    def on_any_event(self, event):
        # Loga todos os eventos para depuração
        logging.debug(f"Evento detectado: {event.event_type} - {event.src_path}")
        if event.event_type == 'modified' and not event.is_directory and not event.src_path.endswith((".tmp", ".log")):
            logging.info(f"Arquivo modificado: {event.src_path}")
            check_suspicious_process()

def check_suspicious_process():
    try:
        for proc in psutil.process_iter(['name', 'cpu_percent', 'open_files']):
            try:
                cpu_percent = proc.cpu_percent(interval=0.1)
                open_files = proc.info['open_files'] or []
                if cpu_percent > 50 or len(open_files) > 10:
                    logging.warning(
                        f"Processo suspeito: {proc.info['name']} (PID: {proc.pid}), "
                        f"CPU: {cpu_percent}%, Arquivos abertos: {len(open_files)}"
                    )
                    proc.suspend()
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
    except Exception as e:
        logging.error(f"Erro ao verificar processos: {e}")

def main():
    monitor_path = r"C:\Monitorado"
    
    if not os.path.exists(monitor_path):
        logging.error(f"Diretório {monitor_path} não existe. Criando...")
        os.makedirs(monitor_path)

    observer = Observer()
    observer.schedule(FileMonitor(), path=monitor_path, recursive=True)
    
    logging.info(f"Iniciando monitoramento em {monitor_path}")
    observer.start()
    
    try:
        while True:
            time.sleep(2)  # Aumentado para reduzir uso de CPU
    except KeyboardInterrupt:
        logging.info("Monitoramento interrompido pelo usuário")
        observer.stop()
    except Exception as e:
        logging.error(f"Erro no monitoramento: {e}")
    finally:
        observer.stop()
        observer.join()

if __name__ == "__main__":
    main() 