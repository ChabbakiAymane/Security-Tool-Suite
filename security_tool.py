#!/usr/bin/env python3
import hashlib
import random
import string
import re
import subprocess
import socket
import requests
import paramiko
import os
import psutil
import time
import math
from datetime import datetime
from collections import defaultdict

class PasswordSecurity:
    def __init__(self):
        # Lista estesa di parole comuni da evitare
        self.common_words = set([
            # Password comuni
            "123456", "password", "qwerty", "admin", "welcome", "letmein",
            "monkey", "dragon", "football", "baseball", "abc123", "111111",
            "mustang", "access", "shadow", "master", "michael", "superman",
            "696969", "123123", "batman", "trustno1", "killer", "manager",
            
            # Parole comuni italiane
            "ciao", "casa", "amore", "vita", "sole", "luna", "mare", "terra",
            "cielo", "fuoco", "acqua", "aria", "tempo", "giorno", "notte",
            "estate", "inverno", "primavera", "autunno", "anno", "mese",
            
            # Termini informatici
            "admin", "root", "user", "guest", "test", "demo", "login", "pass",
            "password", "system", "database", "server", "client", "network",
            "security", "backup", "web", "host", "domain", "email", "mail",
            
            # Nomi propri comuni
            "mario", "luigi", "giovanni", "paolo", "marco", "andrea", "giuseppe",
            "antonio", "maria", "anna", "laura", "sara", "giulia", "rosa",
            
            # Mesi e giorni
            "gennaio", "febbraio", "marzo", "aprile", "maggio", "giugno",
            "luglio", "agosto", "settembre", "ottobre", "novembre", "dicembre",
            "lunedi", "martedi", "mercoledi", "giovedi", "venerdi", "sabato", "domenica"
        ])
        
        # Aggiungi versioni maiuscole e con prime lettere maiuscole
        additional_words = set()
        for word in self.common_words:
            additional_words.add(word.upper())
            additional_words.add(word.capitalize())
        self.common_words.update(additional_words)

    def contains_common_word(self, password):
        """
        Verifica se la password contiene parole comuni
        """
        # Controlla sequenze di almeno 4 caratteri
        for i in range(len(password) - 3):
            for j in range(i + 4, len(password) + 1):
                substring = password[i:j]
                if substring.lower() in self.common_words:
                    return True
        return False

    def generate_secure_password(self, length=16):
        """
        Genera password sicure con criteri avanzati ed evita parole di senso compiuto
        """
        characters = string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|"
        max_attempts = 100  # Previeni loop infiniti
        
        for _ in range(max_attempts):
            password = ''.join(random.choice(characters) for i in range(length))
            
            # Verifica tutti i criteri
            if (any(c.islower() for c in password) and
                any(c.isupper() for c in password) and
                sum(c.isdigit() for c in password) >= 3 and
                sum(c in "!@#$%^&*()_+-=[]{}|" for c in password) >= 3 and
                not self.contains_common_word(password)):
                return password
                
        raise Exception("Impossibile generare una password che soddisfi tutti i criteri")

    def check_password_strength(self, password):
        """
        Analizza la forza di una password con controlli avanzati
        """
        score = 0
        feedback = []

        # Controllo lunghezza
        if len(password) >= 16:
           score += 2
        elif len(password) >= 12:
           score += 1
        else:
          feedback.append("Password troppo corta (minimo 12 caratteri consigliati)")

        # Controllo complessità
        if any(c.islower() for c in password):
            score += 1
        else:
         feedback.append("Mancano lettere minuscole")

        if any(c.isupper() for c in password):
            score += 1
        else:
            feedback.append("Mancano lettere maiuscole")

        if sum(c.isdigit() for c in password) >= 3:
            score += 1
        else:
            feedback.append("Servono almeno 3 numeri")

        if sum(c in "!@#$%^&*()_+-=[]{}|" for c in password) >= 3:
            score += 2
        else:
            feedback.append("Servono almeno 3 caratteri speciali")

        # Controllo parole comuni
        if self.contains_common_word(password):
            score = max(0, score - 3)  # Penalità significativa
            feedback.append("La password contiene parole comuni o di senso compiuto")

        # Calcolo entropia
        char_set_size = (
            sum(bool(re.search(pattern, password)) for pattern in 
            [r'[a-z]', r'[A-Z]', r'\d', r'[!@#$%^&*()_+-=\[\]{}|]'])
        ) * 26  # Approssimazione della dimensione del set di caratteri

        entropy = math.log2(char_set_size) * len(password) if char_set_size > 0 else 0

        # Valutazione finale
        strength_levels = ["Molto debole", "Debole", "Media", "Forte", "Molto forte"]

        # Nuova logica per livelli di forza
        if score < 2:
            final_score = 0  # Molto debole
        elif score < 4:
            final_score = 1  # Debole
        elif score < 6:
            final_score = 2  # Media
        elif score < 8:
            final_score = 3  # Forte
        else:
         final_score = 4  # Molto forte

        # Se contiene parole comuni, limita il livello massimo a "Media"
        if self.contains_common_word(password):
            final_score = min(2, final_score)

        return {
            "score": score,
            "strength": strength_levels[final_score],
            "entropy": entropy,
            "feedback": feedback
        }


class NetworkScanner:
    def __init__(self):
        self.connections = defaultdict(list)
        self.suspicious_ports = {
            20: 'FTP Data',
            21: 'FTP Control',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            67: 'DHCP Server',
            68: 'DHCP Client',
            80: 'HTTP',
            110: 'POP3',
            123: 'NTP',
            137: 'NetBIOS Name',
            138: 'NetBIOS Datagram',
            139: 'NetBIOS Session',
            143: 'IMAP',
            161: 'SNMP',
            162: 'SNMP Trap',
            389: 'LDAP',
            443: 'HTTPS',
            445: 'Microsoft DS',
            465: 'SMTPS',
            514: 'Syslog',
            993: 'IMAPS',
            995: 'POP3S',
            1433: 'MSSQL',
            1434: 'MSSQL Browser',
            3306: 'MySQL',
            3389: 'RDP',
            4444: 'Metasploit',
            5432: 'PostgreSQL',
            5900: 'VNC',
            6660: 'IRC',
            8080: 'HTTP Proxy',
            31337: 'Back Orifice'
        }

    def get_process_details(self, pid):
        """
        Ottiene dettagli del processo dato il PID
        """
        try:
            process = psutil.Process(pid)
            return {
                'name': process.name(),
                'username': process.username(),
                'status': process.status(),
                'cpu_percent': process.cpu_percent(),
                'memory_percent': process.memory_percent()
            }
        except:
            return {
                'name': 'Sconosciuto',
                'username': 'N/A',
                'status': 'N/A',
                'cpu_percent': 0,
                'memory_percent': 0
            }

    def scan_local_ports(self, start_port=1, end_port=65535):
        """
        Scansione approfondita delle porte locali
        """
        print(f"\nScansione delle porte da {start_port} a {end_port}...")
        print("Questo potrebbe richiedere alcuni minuti...")
        
        open_ports = []
        total_ports = end_port - start_port + 1
        scanned_ports = 0
        
        for port in range(start_port, end_port + 1):
            scanned_ports += 1
            if scanned_ports % 1000 == 0:
                progress = (scanned_ports / total_ports) * 100
                print(f"Progresso: {progress:.1f}% completato")
            
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.1)
                    result = s.connect_ex(('127.0.0.1', port))
                    if result == 0:
                        service = "Sconosciuto"
                        try:
                            service = socket.getservbyport(port)
                        except:
                            if port in self.suspicious_ports:
                                service = self.suspicious_ports[port]
                        
                        # Ottieni connessioni attive per questa porta
                        connections = psutil.net_connections()
                        for conn in connections:
                            if conn.laddr.port == port:
                                proc_details = self.get_process_details(conn.pid) if conn.pid else None
                                open_ports.append({
                                    'port': port,
                                    'service': service,
                                    'process': proc_details,
                                    'remote_addr': conn.raddr.ip if conn.raddr else None,
                                    'status': conn.status
                                })
                                break
                        else:
                            open_ports.append({
                                'port': port,
                                'service': service,
                                'process': None,
                                'remote_addr': None,
                                'status': 'LISTEN'
                            })
            except:
                continue
                
        return open_ports

    def monitor_network_traffic(self, duration=30):
        """
        Monitora il traffico di rete per il periodo specificato
        """
        print(f"\nMonitoraggio del traffico di rete per {duration} secondi...")
        
        # Raccogli statistiche iniziali
        initial_stats = psutil.net_io_counters()
        
        # Monitora le connessioni nel tempo
        start_time = time.time()
        connections_log = []
        
        while (time.time() - start_time) < duration:
            try:
                connections = psutil.net_connections(kind='inet')
                timestamp = datetime.now()
                
                for conn in connections:
                    if conn.status == 'ESTABLISHED':
                        proc_details = self.get_process_details(conn.pid) if conn.pid else None
                        connection_info = {
                            'timestamp': timestamp,
                            'local_address': f"{conn.laddr.ip}:{conn.laddr.port}",
                            'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A",
                            'status': conn.status,
                            'process': proc_details
                        }
                        connections_log.append(connection_info)
                
                time.sleep(1)
                
            except Exception as e:
                print(f"Errore durante il monitoraggio: {str(e)}")
                continue
        
        # Raccogli statistiche finali
        final_stats = psutil.net_io_counters()
        
        # Calcola statistiche del traffico
        traffic_stats = {
            'bytes_sent': final_stats.bytes_sent - initial_stats.bytes_sent,
            'bytes_recv': final_stats.bytes_recv - initial_stats.bytes_recv,
            'packets_sent': final_stats.packets_sent - initial_stats.packets_sent,
            'packets_recv': final_stats.packets_recv - initial_stats.packets_recv
        }
        
        return {
            'connections': connections_log,
            'traffic_stats': traffic_stats
        }

    def analyze_suspicious_activity(self, connections_log):
        """
        Analizza le connessioni per attività sospette
        """
        suspicious_activities = []
        
        # Analizza ogni connessione
        for conn in connections_log:
            # Controlla porte sospette
            local_port = int(conn['local_address'].split(':')[1])
            remote_port = int(conn['remote_address'].split(':')[1]) if conn['remote_address'] != "N/A" else 0
            
            if local_port in self.suspicious_ports or remote_port in self.suspicious_ports:
                suspicious_activities.append({
                    'timestamp': conn['timestamp'],
                    'type': 'Porta sospetta',
                    'details': f"Connessione su porta {local_port if local_port in self.suspicious_ports else remote_port} "
                              f"({self.suspicious_ports.get(local_port) or self.suspicious_ports.get(remote_port)})"
                })
            
            # Controlla processi sospetti
            if conn['process'] and conn['process']['name'].lower() in ['nc', 'netcat', 'ncat', 'socat']:
                suspicious_activities.append({
                    'timestamp': conn['timestamp'],
                    'type': 'Processo sospetto',
                    'details': f"Rilevato utilizzo di {conn['process']['name']}"
                })
        
        return suspicious_activities

class WebSecurityTester:
    def __init__(self):
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
    
    def test_sql_injection(self, url):
        """
        Test avanzato di SQL injection
        """
        payloads = [
            "' OR '1'='1",
            "' UNION SELECT NULL--",
            "' OR '1'='1' --",
            "admin'--",
            "1' ORDER BY 1--",
            "1' ORDER BY 2--",
            "1' UNION SELECT table_name,NULL FROM information_schema.tables--",
            "1' AND sleep(5)--",
            "1' AND benchmark(2000000,SHA1(1))--",
            "'; DROP TABLE users--"
        ]
        
        print("\nTest SQL Injection in corso...")
        vulnerabilities = []
        try:
            for payload in payloads:
                print(f"Testing payload: {payload}")
                response = requests.get(
                    f"{url}?id={payload}", 
                    headers=self.headers,
                    timeout=10
                )
                if any(error in response.text.lower() for error in [
                    'sql', 'mysql', 'sqlite', 'postgresql', 'oracle',
                    'syntax error', 'timeout', 'unmarshalled'
                ]):
                    vulnerabilities.append(f"Potenziale SQLi trovata con: {payload}")
        except Exception as e:
            print(f"Errore durante il test SQL injection: {str(e)}")
        return vulnerabilities

    def test_xss(self, url):
        """
        Test avanzato di XSS
        """
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<iframe onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "\"><script>alert('XSS')</script>",
            "'><script>alert('XSS')</script>",
            "<scr<script>ipt>alert('XSS')</script>",
            "';alert('XSS');//"
        ]
        
        print("\nTest XSS in corso...")
        findings = []
        try:
            for payload in payloads:
                print(f"Testing payload: {payload}")
                response = requests.get(
                    f"{url}?q={payload}",
                    headers=self.headers,
                    timeout=10
                )
                if payload.lower() in response.text.lower():
                    findings.append(f"Potenziale XSS trovato con: {payload}")
        except Exception as e:
            print(f"Errore durante il test XSS: {str(e)}")
        return findings

def print_menu():
    """
    Stampa il menu principale
    """
    print("\n=== Security Analysis Tool ===")
    print("1. Gestione Password")
    print("2. Scansione di Rete")
    print("3. Test Sicurezza Web")
    print("0. Esci")
    print("============================")

def print_network_menu():
    """
    Stampa il menu della scansione di rete
    """
    print("\n=== Scansione di Rete ===")
    print("1. Scansione porte complete")
    print("2. Scansione porte veloci (1-1024)")
    print("3. Monitoraggio traffico di rete")
    print("0. Torna al menu principale")
    print("========================")

def password_menu():
    """
    Menu gestione password
    """
    ps = PasswordSecurity()
    while True:
        print("\n=== Gestione Password ===")
        print("1. Genera password sicura")
        print("2. Verifica forza password")
        print("0. Torna al menu principale")
        
        choice = input("\nScegli un'opzione: ").strip()
        
        if choice == "1":
            try:
                length_input = input("Lunghezza password desiderata (min 12): ").strip()
                if not length_input:
                    print("Errore: Inserisci un numero valido")
                    continue
                    
                length = int(length_input)
                password = ps.generate_secure_password(max(length, 12))
                print(f"\nPassword generata: {password}")
                result = ps.check_password_strength(password)
                print(f"Forza: {result['strength']}")
                print(f"Score: {result['score']}/8")
                print(f"Entropia: {result['entropy']:.2f}")
            except ValueError:
                print("Errore: Inserisci un numero valido")
                
        elif choice == "2":
            password = input("Inserisci la password da verificare: ")
            result = ps.check_password_strength(password)
            print(f"\nForza: {result['strength']}")
            print(f"Score: {result['score']}/8")
            print(f"Entropia: {result['entropy']:.2f}")
            if result['feedback']:
                print("Feedback:", ", ".join(result['feedback']))
                
        elif choice == "0":
            break
        else:
            print("Opzione non valida!")
def web_security_menu():
    """
    Menu test sicurezza web
    """
    ws = WebSecurityTester()
    while True:
        print("\n=== Test Sicurezza Web ===")
        print("1. Test SQL Injection")
        print("2. Test XSS")
        print("0. Torna al menu principale")
        
        choice = input("\nScegli un'opzione: ")
        
        if choice in ["1", "2"]:
            url = input("Inserisci l'URL da testare: ")
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
                
            if choice == "1":
                results = ws.test_sql_injection(url)
                if results:
                    print("\nVulnerabilità SQL Injection trovate:")
                    for vuln in results:
                        print(f"- {vuln}")
                else:
                    print("\nNessuna vulnerabilità SQL Injection evidente trovata")
                    
            elif choice == "2":
                results = ws.test_xss(url)
                if results:
                    print("\nVulnerabilità XSS trovate:")
                    for vuln in results:
                        print(f"- {vuln}")
                else:
                    print("\nNessuna vulnerabilità XSS evidente trovata")
                    
        elif choice == "0":
            break

def network_menu():
    """
    Menu scansione di rete
    """
    ns = NetworkScanner()
    while True:
        print("\n=== Scansione di Rete ===")
        print("1. Scansione porte complete")
        print("2. Scansione porte veloci (1-1024)")
        print("3. Monitoraggio traffico di rete")
        print("0. Torna al menu principale")
        
        choice = input("\nScegli un'opzione: ")
        
        if choice == "1":
            print("\nAvvio scansione porte completa (1-65535)...")
            open_ports = ns.scan_local_ports()
            print("\nRisultati della scansione:")
            for port_info in open_ports:
                print(f"\nPorta: {port_info['port']}")
                print(f"Servizio: {port_info['service']}")
                if port_info['process']:
                    print(f"Processo: {port_info['process']['name']}")
                    print(f"Utente: {port_info['process']['username']}")
                    print(f"CPU: {port_info['process']['cpu_percent']}%")
                    print(f"Memoria: {port_info['process']['memory_percent']:.1f}%")
                if port_info['remote_addr']:
                    print(f"Indirizzo remoto: {port_info['remote_addr']}")
                print(f"Stato: {port_info['status']}")
                
        elif choice == "2":
            print("\nAvvio scansione porte veloci (1-1024)...")
            open_ports = ns.scan_local_ports(1, 1024)
            print("\nRisultati della scansione:")
            for port_info in open_ports:
                print(f"\nPorta: {port_info['port']}")
                print(f"Servizio: {port_info['service']}")
                if port_info['process']:
                    print(f"Processo: {port_info['process']['name']}")
                if port_info['remote_addr']:
                    print(f"Indirizzo remoto: {port_info['remote_addr']}")
                print(f"Stato: {port_info['status']}")
                
        elif choice == "3":
            duration = int(input("Durata monitoraggio in secondi (default: 30): ") or "30")
            print(f"\nMonitoraggio traffico per {duration} secondi...")
            results = ns.monitor_network_traffic(duration)
            
            # Stampa statistiche del traffico
            stats = results['traffic_stats']
            print("\nStatistiche del traffico:")
            print(f"Bytes inviati: {stats['bytes_sent']:,}")
            print(f"Bytes ricevuti: {stats['bytes_recv']:,}")
            print(f"Pacchetti inviati: {stats['packets_sent']:,}")
            print(f"Pacchetti ricevuti: {stats['packets_recv']:,}")
            
            # Analizza connessioni sospette
            suspicious = ns.analyze_suspicious_activity(results['connections'])
            if suspicious:
                print("\nAttività sospette rilevate:")
                for activity in suspicious:
                    print(f"\nTipo: {activity['type']}")
                    print(f"Timestamp: {activity['timestamp']}")
                    print(f"Dettagli: {activity['details']}")
            
            # Mostra connessioni attive
            print("\nConnessioni attive durante il monitoraggio:")
            for conn in results['connections']:
                print(f"\nTimestamp: {conn['timestamp']}")
                print(f"Indirizzo locale: {conn['local_address']}")
                print(f"Indirizzo remoto: {conn['remote_address']}")
                print(f"Stato: {conn['status']}")
                if conn['process']:
                    print(f"Processo: {conn['process']['name']}")
                    print(f"Utente: {conn['process']['username']}")
                    
        elif choice == "0":
            break

def main():
    print("\nInitializing Security Analysis Tool...")
    print("Versione 1.0 - Sviluppato per analisi di sicurezza")
    print("ATTENZIONE: Utilizzare solo su sistemi autorizzati")
    
    while True:
        print("\n=== Security Analysis Tool ===")
        print("1. Gestione Password")
        print("2. Scansione di Rete")
        print("3. Test Sicurezza Web")
        print("0. Esci")
        print("============================")
        
        choice = input("\nScegli un'opzione: ")
        
        if choice == "1":
            password_menu()
        elif choice == "2":
            network_menu()
        elif choice == "3":
            web_security_menu()
        elif choice == "0":
            print("\nChiusura programma...")
            break
        else:
            print("\nOpzione non valida!")

if __name__ == "__main__":
    main()