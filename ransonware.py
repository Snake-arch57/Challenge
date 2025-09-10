# simulate_ransomware.py
import os, time
from pathlib import Path
 
# Diretório de teste
TEST_DIR = Path("C:/Users/Public/ransomware_sim")
TEST_DIR.mkdir(parents=True, exist_ok=True)
 
def make_random_file(path, size_kb=64):
    with open(path, "wb") as f:
        f.write(os.urandom(size_kb * 1024))  # conteúdo aleatório = entropia alta
 
if __name__ == "__main__":
    print("[INFO] Iniciando simulação de ransomware seguro...")
    for i in range(200):  # cria 200 arquivos (ajuste se quiser)
        file_path = TEST_DIR / f"sim_{i}.bin"
        make_random_file(file_path, size_kb=128)  # 128KB cada
        time.sleep(0.05)  # delay pequeno para simular cifragem rápida
    print("[INFO] Simulação concluída.")