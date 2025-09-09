import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time
import logging
import os
import stat
import getpass

# Configura o logging
logging.basicConfig(
    level=logging.DEBUG,
    filename="ransomware.log",
    format="%(asctime)s - %(levelname)s - %(message)s",
    encoding="utf-8"
)

class FileMonitor(FileSystemEventHandler):
    def __init__(self, honeypot_files):
        self.honeypot_files = honeypot_files  # Dicionário {pasta: [arquivos isca]}
        self.last_permissions = {}
        for directory, files in honeypot_files.items():
            for file_path in files:
                if os.path.exists(file_path):
                    self.last_permissions[file_path] = os.stat(file_path).st_mode

    def on_any_event(self, event):
        if event.is_directory:
            return
        
        # Verifica eventos em arquivos isca
        for directory, files in self.honeypot_files.items():
            if event.src_path in files:
                if event.event_type == 'modified':
                    logging.warning(f"Arquivo isca modificado em {directory}: {event.src_path}")
                    alert_honeypot(event.src_path, "modificado", directory)
                elif event.event_type == 'deleted':
                    logging.warning(f"Arquivo isca excluído em {directory}: {event.src_path}")
                    alert_honeypot(event.src_path, "excluído", directory)
                elif event.event_type == 'moved':
                    logging.warning(f"Arquivo isca renomeado em {directory}: {event.src_path} -> {event.dest_path}")
                    alert_honeypot(event.src_path, f"renomeado para {event.dest_path}", directory)
                elif event.event_type == 'created':
                    logging.warning(f"Arquivo isca recriado em {directory}: {event.src_path}")
                    alert_honeypot(event.src_path, "recriado", directory)
        
        # Verifica alterações de permissões
        for directory, files in self.honeypot_files.items():
            for file_path in files:
                if os.path.exists(file_path):
                    current_mode = os.stat(file_path).st_mode
                    if current_mode != self.last_permissions.get(file_path):
                        logging.warning(f"Permissões alteradas em arquivo isca em {directory}: {file_path}")
                        alert_honeypot(file_path, "permissões alteradas", directory)
                        self.last_permissions[file_path] = current_mode
        
        # Verifica processos suspeitos para modificações
        if event.event_type == 'modified' and not event.src_path.endswith((".tmp", ".log")):
            check_suspicious_process()

def alert_honeypot(file_path, action, directory):
    message = f"ALERTA CRÍTICO: Possível ransomware detectado em {directory}! Arquivo isca {file_path} foi {action}!"
    print(message)
    logging.critical(message)
    
    # Se o arquivo foi excluído, tenta matar o processo suspeito
    if action == "excluído":
        kill_suspicious_process()

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

def kill_suspicious_process():
    try:
        for proc in psutil.process_iter(['name', 'cpu_percent', 'open_files']):
            try:
                cpu_percent = proc.cpu_percent(interval=0.1)
                open_files = proc.info['open_files'] or []
                if cpu_percent > 50 or len(open_files) > 10:
                    logging.critical(
                        f"Encerrando processo suspeito: {proc.info['name']} (PID: {proc.pid}), "
                        f"CPU: {cpu_percent}%, Arquivos abertos: {len(open_files)}"
                    )
                    proc.terminate()  # Encerra o processo
                    logging.info(f"Processo {proc.info['name']} (PID: {proc.pid}) encerrado.")
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
    except Exception as e:
        logging.error(f"Erro ao encerrar processos: {e}")

def setup_honeypot(directories):
    honeypot_files = {}
    file_extensions = [".docx", ".pdf", ".xlsx", ".txt", ".jpg"]
    
    for directory in directories:
        if not os.path.exists(directory):
            try:
                os.makedirs(directory)
                logging.info(f"Diretório criado: {directory}")
            except Exception as e:
                logging.error(f"Erro ao criar diretório {directory}: {e}")
                continue
        
        honeypot_files[directory] = []
        # Cria 3 arquivos isca por pasta
        for i, ext in enumerate(file_extensions[:3]):
            file_path = os.path.join(directory, f"documento_critico_{i}{ext}")
            try:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write("Arquivo de teste para honeypot.")
                honeypot_files[directory].append(os.path.abspath(file_path))
                logging.info(f"Arquivo isca criado em {directory}: {file_path}")
            except Exception as e:
                logging.error(f"Erro ao criar arquivo isca {file_path}: {e}")
    
    return honeypot_files

def main():
    # Define pastas críticas
    user = getpass.getuser()
    critical_folders = [
        r"C:\Monitorado",
        os.path.join(os.path.expanduser("~"), "Documents"),
        os.path.join(os.path.expanduser("~"), "Desktop")
    ]
    
    # Configura honeypot
    honeypot_files = setup_honeypot(critical_folders)
    
    # Configura monitoramento para cada pasta
    observer = Observer()
    for directory in honeypot_files.keys():
        observer.schedule(FileMonitor(honeypot_files), path=directory, recursive=False)
        logging.info(f"Iniciando monitoramento em {directory}")
    
    observer.start()
    
    try:
        while True:
            time.sleep(2)
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