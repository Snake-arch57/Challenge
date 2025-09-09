#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Entropy Sentinel — com Honeypot Mode (scan, watch, honeypot)
"""

from __future__ import annotations
import os
import time
import psutil
import logging
import getpass
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

import click
from entropy_sentinel import file_entropy, create_canaries, alert, iter_files, EntropyEventHandler

# ---------------- CONFIG ----------------
WHITELIST = {"explorer.exe", "SearchApp.exe", "svchost.exe", "RuntimeBroker.exe"}
LOG_FILE = "honeypot_entropy.log"
logging.basicConfig(
    level=logging.DEBUG,
    filename=LOG_FILE,
    format="%(asctime)s - %(levelname)s - %(message)s",
    encoding="utf-8"
)

# ---------------- HONEYPOT ----------------
class HoneypotHandler(FileSystemEventHandler):
    def __init__(self, honeypot_files):
        self.honeypot_files = honeypot_files

    def on_any_event(self, event):
        if event.is_directory:
            return
        for directory, files in self.honeypot_files.items():
            if event.src_path in files:
                msg = f"HONEYPOT ALERT: {event.src_path} {event.event_type} em {directory}"
                print(msg)
                logging.warning(msg)
                check_processes()

def setup_honeypot(directories):
    honeypot_files = {}
    file_extensions = [".docx", ".pdf", ".txt"]
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        honeypot_files[directory] = []
        for i, ext in enumerate(file_extensions):
            path = os.path.join(directory, f"honeypot_{i}{ext}")
            with open(path, "w", encoding="utf-8") as f:
                f.write("Arquivo isca honeypot.\n")
            honeypot_files[directory].append(os.path.abspath(path))
    return honeypot_files

def check_processes():
    for proc in psutil.process_iter(["pid", "name", "cpu_percent", "open_files"]):
        try:
            name = proc.info["name"]
            if name in WHITELIST:
                continue
            cpu = proc.cpu_percent(interval=0.1)
            opened = proc.info.get("open_files") or []
            if cpu > 50 or len(opened) > 10:
                logging.warning(f"[SUSPEITO] {name} PID {proc.pid}, CPU {cpu}%, arquivos {len(opened)}")
                try:
                    proc.suspend()
                    proc.terminate()
                except Exception as e:
                    logging.error(f"Erro ao suspender/terminar {name}: {e}")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

# ---------------- CLI ----------------
@click.group()
def cli():
    pass

@cli.command()
@click.argument("target", type=click.Path(path_type=Path, exists=True))
@click.option("--threshold", type=float, default=7.6)
@click.option("--include-hidden", is_flag=True)
def scan(target, threshold, include_hidden):
    """Scan entropia"""
    files = iter_files(target, include_hidden)
    suspects = [file_entropy(f, threshold) for f in files if file_entropy(f, threshold).suspicious]
    print(f"SCAN terminou. Suspeitos: {len(suspects)}")

@cli.command()
@click.argument("target", type=click.Path(path_type=Path, exists=True))
@click.option("--threshold", type=float, default=7.6)
@click.option("--canaries", type=int, default=2)
def watch(target, threshold, canaries):
    """Monitor entropia + canários"""
    canary_names = create_canaries(target, canaries)
    observer = Observer()
    handler = EntropyEventHandler(target, threshold, None, canary_names)
    observer.schedule(handler, str(target), recursive=True)
    observer.start()
    print("WATCH rodando...")
    try:
        while True:
            time.sleep(2)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

@cli.command()
@click.option("--dirs", multiple=True, type=click.Path(path_type=Path), help="Pastas para honeypot")
@click.option("--recursive", is_flag=True, help="Monitorar também subpastas")
def honeypot(dirs, recursive):
    """Cria e vigia honeypot"""
    user = getpass.getuser()

    # se usuário não passar nada, vai no default
    if not dirs:
        dirs = [
            r"C:\Monitorado",
            os.path.join(os.path.expanduser("~"), "Documents"),
            os.path.join(os.path.expanduser("~"), "Desktop")
        ]

    dirs = [str(Path(d).expanduser()) for d in dirs]

    honeypots = setup_honeypot(dirs)
    observer = Observer()
    handler = HoneypotHandler(honeypots)
    for d in honeypots:
        observer.schedule(handler, path=d, recursive=recursive)
    observer.start()
    print(f"HONEYPOT rodando em: {', '.join(dirs)} (recursive={recursive})")
    try:
        while True:
            time.sleep(2)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    cli()
