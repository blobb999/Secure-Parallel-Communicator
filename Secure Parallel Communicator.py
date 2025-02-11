import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import socket
import threading
import datetime
import time
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend
import os
import secrets
import base64
import tkinter.filedialog as fd

class EnhancedMultiConnectionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Parallel Communicator V1.0")
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.key_rotation_interval = 30  # z. B. 30 Sekunden

        # Netzwerkvariablen
        self.server_sockets = []
        self.client_sockets = {}
        self.connection_pool = {}
        self.message_buffer = {}
        self.lock = threading.Lock()
        self.running = True
        self.shutting_down = False

        # ACK-Events für den Multiplexing-Mechanismus
        self.pending_acks = {}

        # RSA-Schlüssel generieren
        self.server_rsa_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.server_rsa_public_key = self.server_rsa_private_key.public_key()
        self.client_rsa_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.client_rsa_public_key = self.client_rsa_private_key.public_key()

        # GUI initialisieren
        self.create_widgets()
        self.setup_global_context_menu()

        # Starte Key Rotation Thread
        self.start_key_rotation()

        # Konfiguration
        self.config = {
            'max_connections': 8,
            'timeout': 2,
            'heartbeat_interval': 5,
            'message_timeout': 30
        }

        self.update_status()
        
    def create_widgets(self):
        # Server Section
        ttk.Label(self.root, text="Server Configuration", style='Header.TLabel').grid(row=0, column=0, columnspan=3, pady=5)

        ttk.Label(self.root, text="Server IP:").grid(row=1, column=0, sticky="e")
        self.server_ip = ttk.Entry(self.root, width=20)
        self.server_ip.grid(row=1, column=1, padx=5, pady=2)
        self.server_ip.insert(0, "192.168.2.105")

        ttk.Label(self.root, text="Base Port:").grid(row=2, column=0, sticky="e")
        self.base_port = ttk.Entry(self.root, width=10)
        self.base_port.grid(row=2, column=1, padx=5, pady=2)
        self.base_port.insert(0, "5000")

        ttk.Label(self.root, text="Connections:").grid(row=3, column=0, sticky="e")
        self.conn_selector = ttk.Combobox(self.root, values=[2,4,6,8], width=3)
        self.conn_selector.grid(row=3, column=1, sticky="w")
        self.conn_selector.current(1)

        self.start_server_btn = ttk.Button(self.root, text="Start Server", command=self.start_server)
        self.start_server_btn.grid(row=4, column=0, columnspan=3, pady=5)

        # Client Section
        ttk.Label(self.root, text="Client Configuration", style='Header.TLabel').grid(row=5, column=0, columnspan=3, pady=5)

        ttk.Label(self.root, text="Server IP:").grid(row=6, column=0, sticky="e")
        self.client_ip = ttk.Entry(self.root, width=20)
        self.client_ip.grid(row=6, column=1, padx=5, pady=2)
        self.client_ip.insert(0, "192.168.2.105")

        ttk.Label(self.root, text="Base Port:").grid(row=7, column=0, sticky="e")
        self.client_port = ttk.Entry(self.root, width=10)
        self.client_port.grid(row=7, column=1, padx=5, pady=2)
        self.client_port.insert(0, "5000")

        self.connect_client_btn = ttk.Button(self.root, text="Connect as Client", command=self.start_client)
        self.connect_client_btn.grid(row=8, column=0, columnspan=3, pady=5)

        # Statusbereich hinzufügen
        status_frame = ttk.LabelFrame(self.root, text="Status", padding=(10, 10))
        status_frame.grid(row=12, column=0, columnspan=3, sticky="ew", padx=5, pady=5)

        # Handshake Status
        self.handshake_status_label = ttk.Label(status_frame, text="Handshake: Not connected")
        self.handshake_status_label.grid(row=0, column=0, sticky="w", padx=5, pady=2)

        # Ports Status (Platzhalter: später wird hier dynamisch pro Port ein Label angelegt)
        ports_status_frame = ttk.Frame(status_frame)
        ports_status_frame.grid(row=1, column=0, sticky="w", padx=5, pady=2)
        self.ports_status_frame = ports_status_frame  # Merker zum späteren Aktualisieren

        # Key Rotation Status (Countdown)
        self.key_rotation_status_label = ttk.Label(status_frame, text="Key Rotation: N/A")
        self.key_rotation_status_label.grid(row=2, column=0, sticky="w", padx=5, pady=2)

        # Message Box
        ttk.Label(self.root, text="Communication Log", style='Header.TLabel').grid(row=9, column=0, columnspan=3, pady=5)
        self.message_box = scrolledtext.ScrolledText(
            self.root, 
            width=60, 
            height=15,
            wrap=tk.WORD,
            state='normal'
        )
        self.message_box.grid(row=10, column=0, columnspan=3, padx=5, pady=5)
        self.message_box.bind('<KeyPress>', lambda e: 'break')

        # Message Input 
        self.message_input = ttk.Entry(self.root, width=50)
        self.message_input.grid(row=11, column=0, padx=5, pady=5, columnspan=2)
        self.send_btn = ttk.Button(self.root, text="Send", command=self.send_message)
        self.send_btn.grid(row=11, column=2, padx=5, pady=5)

        # Neuer Button "Send File"
        self.send_file_btn = ttk.Button(self.root, text="Send File", command=self.send_file)
        self.send_file_btn.grid(row=11, column=3, padx=5, pady=5)

        # Style Configuration
        style = ttk.Style()
        style.configure('Header.TLabel', font=('Helvetica', 10, 'bold'))
        style.configure('TButton', padding=5)
        self.message_box.tag_config('send', foreground='blue')
        self.message_box.tag_config('receive', foreground='green')
        self.message_box.tag_config('error', foreground='red')
        self.message_box.tag_config('system', foreground='gray')
        

    def setup_global_context_menu(self):
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="Kopieren", command=self.copy_text)
        self.context_menu.add_command(label="Einfügen", command=self.paste_text)
        self.context_menu.add_command(label="Alles auswählen", command=self.select_all_text)

        for widget in [self.message_box, self.message_input, self.server_ip, self.base_port, self.client_ip, self.client_port]:
            widget.bind("<Button-3>", self.show_context_menu)

    def show_context_menu(self, event):
        try:
            self.context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.context_menu.grab_release()

    def copy_text(self):
        try:
            widget = self.root.focus_get()
            if isinstance(widget, tk.Entry):
                text = widget.selection_get()
            elif isinstance(widget, tk.Text):
                if widget.tag_ranges("sel"):
                    text = widget.get("sel.first", "sel.last")
                else:
                    return
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
        except Exception as e:
            self.update_ui(f"[ERROR] Copy failed: {str(e)}", "error")

    def paste_text(self):
        try:
            widget = self.root.focus_get()
            if isinstance(widget, (tk.Entry, tk.Text)):
                text = self.root.clipboard_get()
                widget.insert(tk.INSERT, text)
        except Exception as e:
            self.update_ui(f"[ERROR] Paste failed: {str(e)}", "error")

    def select_all_text(self):
        try:
            widget = self.root.focus_get()
            if isinstance(widget, tk.Entry):
                widget.select_range(0, tk.END)
            elif isinstance(widget, tk.Text):
                widget.tag_add("sel", "1.0", "end")
        except Exception as e:
            self.update_ui(f"[ERROR] Select all failed: {str(e)}", "error")


    def update_status(self):
        # Handshake-Status aktualisieren (clientseitig oder serverseitig; hier ein Beispiel für den Client)
        if self.client_sockets:
            first_port = list(self.client_sockets.keys())[0]
            algorithm = self.client_sockets[first_port].get('algorithm', 'Unknown')
            self.handshake_status_label.config(text=f"Handshake: {algorithm}")
        elif self.connection_pool:
            first_conn = list(self.connection_pool.keys())[0]
            algorithm = self.connection_pool[first_conn].get('algorithm', 'Unknown')
            self.handshake_status_label.config(text=f"Handshake: {algorithm}")
        else:
            self.handshake_status_label.config(text="Handshake: Not connected")

        # Ports-Status aktualisieren
        # Leere zunächst den Container und erstelle Labels für jeden Port
        for widget in self.ports_status_frame.winfo_children():
            widget.destroy()

        # Je nach Modus: entweder Client oder Server anzeigen
        if self.client_sockets:
            items = self.client_sockets.items()
        elif self.connection_pool:
            items = self.connection_pool.items()
        else:
            items = []

        # Erstelle für jeden Eintrag ein Label, das den Port und den Verschlüsselungstyp anzeigt,
        # und einen Statuspunkt (grün = synchron, rot = unsynchron).
        # Wir verwenden hier grid, um alle in einer Zeile anzuordnen.
        col = 0
        for port, info in items:
            algorithm = info.get('algorithm', 'Unknown')
            # Label: "Port {port} ({algorithm})"
            port_label = ttk.Label(self.ports_status_frame, text=f"Port {port} ({algorithm}):", width=20)
            port_label.grid(row=0, column=col, padx=2, pady=2, sticky="w")
            col += 1
            # Statuspunkt
            if info.get('previous_symmetric_key') is None:
                color = "green"
            else:
                color = "red"
            status_dot = tk.Label(self.ports_status_frame, text="●", fg=color)
            status_dot.grid(row=0, column=col, padx=2, pady=2)
            col += 1

        # Key Rotation Status aktualisieren
        if self.next_rotation_time:
            remaining = int(self.next_rotation_time - time.time())
            if remaining < 0:
                remaining = 0
            self.key_rotation_status_label.config(text=f"Key Rotation: Next in {remaining} s")
        else:
            self.key_rotation_status_label.config(text="Key Rotation: N/A")

        # Wiederhole diese Statusaktualisierung alle 1000 ms
        self.root.after(1000, self.update_status)

    def start_server(self):
        try:
            ip = self.server_ip.get()
            base_port = int(self.base_port.get())
            num_conn = int(self.conn_selector.get())

            self.stop_server()

            for port in range(base_port, base_port + num_conn):
                server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server_socket.bind((ip, port))
                server_socket.listen(5)
                self.server_sockets.append(server_socket)
                # Corrected line: Removed conn_id from args
                threading.Thread(
                    target=self.accept_connections,
                    args=(server_socket, port),  # Only pass server_socket and port
                    daemon=True
                ).start()

            self.update_ui(f"[SERVER] Started on {ip}:{base_port}-{base_port+num_conn-1}", "system")
            self.start_heartbeat()

        except Exception as e:
            self.show_error(f"Server error: {str(e)}")


    def start_key_rotation(self):
        def rotation_check():
            while self.running and not self.shutting_down:
                self.next_rotation_time = time.time() + self.key_rotation_interval
                time.sleep(self.key_rotation_interval)
                self.rotate_keys()
        self.rotation_thread = threading.Thread(target=rotation_check, daemon=True)
        self.rotation_thread.start()


    def send_all(self, sock, data):
        total_sent = 0
        while total_sent < len(data):
            try:
                sent = sock.send(data[total_sent:])
                if sent == 0:
                    raise RuntimeError("Socket connection broken")
                total_sent += sent
            except Exception as e:
                self.update_ui(f"[ERROR] Send failed: {str(e)}", "error")
                raise

    def rotate_keys(self):
        if hasattr(self, 'key_rotation_active') and self.key_rotation_active:
            self.update_ui("[WARNING] Key rotation already in progress", "warning")
            return

        self.key_rotation_active = True
        self.update_ui("[INFO] Initiating key rotation...", "system")

        new_key = os.urandom(32)
        backup_keys = {}  # Sichert den alten Schlüssel für einen möglichen Rollback

        with self.lock:
            connections = list(self.connection_pool.items())

        # Sende den neuen Schlüssel an alle Clients und lege ACK-Events an
        for conn_id, conn_info in connections:
            try:
                client_pub_key = conn_info.get('client_public_key')
                if not client_pub_key:
                    continue

                encrypted_key = client_pub_key.encrypt(
                    new_key,
                    padding.OAEP(
                        mgf=padding.MGF1(hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                payload = b"KR" + encrypted_key  # Nachrichtentyp "KR"
                sock = conn_info['socket']
                self.send_all(sock, len(payload).to_bytes(4, 'big') + payload)
                backup_keys[conn_id] = conn_info['symmetric_key']  # Alten Schlüssel sichern

                # Lege ein ACK-Event für diese Verbindung an
                with self.lock:
                    self.pending_acks[conn_id] = threading.Event()
            except Exception as e:
                self.update_ui(f"[ERROR] Sending new key to {conn_id} failed: {str(e)}", "error")

        # Warte auf ACKs über den Multiplexer (Timeout 5 Sekunden)
        confirmed_clients = set()
        with self.lock:
            pending_ids = list(self.pending_acks.keys())
        for conn_id in pending_ids:
            event = self.pending_acks.get(conn_id)
            if event is not None and event.wait(timeout=5):
                confirmed_clients.add(conn_id)
                self.update_ui(f"[SUCCESS] Key rotation confirmed for {conn_id}", "system")
            else:
                self.update_ui(f"[WARNING] No ACK received from {conn_id} within timeout", "warning")

        # Entferne die verarbeiteten ACK-Events
        with self.lock:
            for conn_id in confirmed_clients:
                if conn_id in self.pending_acks:
                    del self.pending_acks[conn_id]

        # Falls nicht alle Clients bestätigt haben, Rollback einleiten
        if len(confirmed_clients) < len(connections):
            self.update_ui("[ERROR] Key rotation aborted due to missing confirmations. Initiating rollback...", "error")
            for conn_id in confirmed_clients:
                try:
                    sock = self.connection_pool[conn_id]['socket']
                    rollback_payload = b"RB"  # Nachrichtentyp "RB" für Rollback
                    self.send_all(sock, len(rollback_payload).to_bytes(4, 'big') + rollback_payload)
                    with self.lock:
                        if conn_id in self.connection_pool:
                            self.connection_pool[conn_id]['symmetric_key'] = backup_keys[conn_id]
                            self.connection_pool[conn_id]['previous_symmetric_key'] = None
                    self.update_ui(f"[SUCCESS] Rollback executed for {conn_id}", "system")
                except Exception as e:
                    self.update_ui(f"[ERROR] Rollback failed for {conn_id}: {str(e)}", "error")
            self.key_rotation_active = False
            return

        # Alle Clients haben bestätigt – starte die Schlüsselübergangsphase
        self.update_ui("[INFO] Activating key transition phase for 10 seconds", "system")
        with self.lock:
            for conn_id in confirmed_clients:
                if conn_id in self.connection_pool:
                    conn_info = self.connection_pool[conn_id]
                    conn_info['previous_symmetric_key'] = backup_keys[conn_id]
                    conn_info['symmetric_key'] = new_key
                    conn_info['key_transition_active'] = True
                    self.update_ui(f"[DEBUG] Rotation for {conn_id}: New key activated", "system")

        time.sleep(10)  # Übergangsphase, in der beide Schlüssel gültig sind

        with self.lock:
            for conn_id in confirmed_clients:
                if conn_id in self.connection_pool:
                    conn_info = self.connection_pool[conn_id]
                    conn_info['previous_symmetric_key'] = None
                    conn_info['key_transition_active'] = False
                    self.update_ui(f"[SUCCESS] Key transition completed for {conn_id}", "system")
        self.key_rotation_active = False


    def receive_messages(self):
        while self.running and not self.shutting_down:
            try:
                with self.lock:
                    sockets = list(self.client_sockets.items())
                for port, sock_info in sockets:
                    sock = sock_info['socket']
                    try:
                        length_bytes = self.receive_all(sock, 4)
                        if not length_bytes:
                            continue
                        length = int.from_bytes(length_bytes, 'big')
                        data = self.receive_all(sock, length)
                        if not data or len(data) < 2:
                            continue

                        msg_type = data[:2]
                        payload = data[2:]

                        # Key Rotation
                        if msg_type == b"KR":
                            new_key = self.client_rsa_private_key.decrypt(
                                payload,
                                padding.OAEP(
                                    mgf=padding.MGF1(hashes.SHA256()),
                                    algorithm=hashes.SHA256(), label=None)
                            )
                            sock_info['previous_symmetric_key'] = sock_info['symmetric_key']
                            sock_info['symmetric_key'] = new_key
                            sock_info['decryption_success_count'] = 0
                            ack_payload = b"AK"
                            ack_message = len(ack_payload).to_bytes(4, 'big') + ack_payload
                            for _ in range(3):
                                try:
                                    self.send_all(sock, ack_message)
                                    break
                                except Exception:
                                    time.sleep(1)
                            self.update_ui(f"[SUCCESS] Key rotated for port {port}", "system")
                            continue

                        # Rollback
                        elif msg_type == b"RB":
                            if sock_info.get('previous_symmetric_key'):
                                sock_info['symmetric_key'] = sock_info['previous_symmetric_key']
                                sock_info['previous_symmetric_key'] = None
                                self.update_ui(f"[SUCCESS] Rollback executed for port {port}", "system")
                            else:
                                self.update_ui(f"[WARNING] Rollback received for port {port} but no previous key available", "warning")
                            continue

                        # File Transfer
                        elif msg_type == b"SF":
                            # Verwende hier den aktuellen Eintrag aus client_sockets (sock_info)
                            keys = [sock_info['symmetric_key']]
                            if sock_info.get('previous_symmetric_key'):
                                keys.append(sock_info['previous_symmetric_key'])
                            decrypted_data = self.decrypt_message(payload, keys, sock_info['algorithm'])
                            # Hier wird der Reassembly-Mechanismus mit dem Typ SF aufgerufen
                            self.process_received_data(decrypted_data, "client", msg_type)
                            continue

                        # Normale Nachrichten
                        elif msg_type == b"NM":
                            keys = [sock_info['symmetric_key']]
                            if sock_info.get('previous_symmetric_key'):
                                keys.append(sock_info['previous_symmetric_key'])
                            decrypted_data = self.decrypt_message(payload, keys, sock_info['algorithm'])
                        # Heartbeat
                        elif msg_type == b"HB":
                            keys = [sock_info['symmetric_key']]
                            if sock_info.get('previous_symmetric_key'):
                                keys.append(sock_info['previous_symmetric_key'])
                            decrypted_data = self.decrypt_message(payload, keys, sock_info['algorithm'])
                            if decrypted_data == "HEARTBEAT":
                                continue
                        else:
                            self.update_ui("[WARNING] Unknown message type received", "warning")
                            continue

                        if decrypted_data:
                            # Für normale Nachrichten wird msg_type b"NM" übergeben
                            self.process_received_data(decrypted_data, "client", b"NM")
                            if sock_info['symmetric_key'] == keys[0]:
                                sock_info['decryption_success_count'] += 1
                            if sock_info['decryption_success_count'] >= 3:
                                sock_info['previous_symmetric_key'] = None
                        else:
                            self.update_ui(f"[ERROR] Decryption failed for port {port}", "error")
                    except socket.timeout:
                        continue
                    except Exception as e:
                        self.update_ui(f"[ERROR] Port {port} error: {str(e)}", "error")
                        with self.lock:
                            if port in self.client_sockets:
                                del self.client_sockets[port]
            except Exception as e:
                self.update_ui(f"[ERROR] Receive error: {str(e)}", "error")

    def receive_all(self, sock, length):
        data = b''
        while len(data) < length:
            try:
                chunk = sock.recv(length - len(data))
                if not chunk:
                    raise ConnectionResetError("Client disconnected unexpectedly")
                data += chunk
            except socket.timeout:
                continue
            except ConnectionResetError as e:
                self.update_ui(f"[ERROR] Connection lost: {str(e)}", "error")
                with self.lock:
                    for conn_id, conn_info in list(self.connection_pool.items()):
                        if conn_info['socket'] == sock:
                            del self.connection_pool[conn_id]
                            break
                return None
            except Exception as e:
                self.update_ui(f"[ERROR] Receive failed: {str(e)}", "error")
                return None
        return data


    def accept_connections(self, server_socket, port):
        while self.running and not self.shutting_down:
            try:
                client_socket, addr = server_socket.accept()
                conn_id = f"{addr[0]}:{addr[1]}"
                client_socket.settimeout(self.config['timeout'])
                with self.lock:
                    self.connection_pool[conn_id] = {
                        'socket': client_socket,
                        'symmetric_key': None,
                        'algorithm': None,
                        'port': port
                    }
                self.update_ui(f"[CONNECTION] New client {conn_id} on port {port}", "system")
                threading.Thread(
                    target=self.handle_client_messages,
                    args=(client_socket, conn_id, port),
                    daemon=True
                ).start()
            except socket.timeout:
                continue
            except Exception as e:
                if not self.shutting_down:
                    self.update_ui(f"[ERROR] Accept failed: {str(e)}", "error")
                    

    def handle_client_messages(self, client_socket, conn_id, port):
        try:
            # Bestimme den Verschlüsselungsalgorithmus anhand des Portindex
            base_port_val = int(self.base_port.get())
            port_index = port - base_port_val
            algorithms = ['aes-256-cbc', 'chacha20']
            algorithm = algorithms[port_index % len(algorithms)]
            
            # Sende den Handshake: Algorithmus und den Server-öffentlichen RSA-Schlüssel
            pem_public = self.server_rsa_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
            handshake_msg = f"{algorithm}:{pem_public}"
            client_socket.send(len(handshake_msg).to_bytes(4, 'big') + handshake_msg.encode('utf-8'))
            
            # Empfange den verschlüsselten symmetrischen Schlüssel des Clients
            length = int.from_bytes(self.receive_all(client_socket, 4), 'big')
            encrypted_key = self.receive_all(client_socket, length)
            
            # Empfange den öffentlichen Schlüssel des Clients
            length_pub = int.from_bytes(self.receive_all(client_socket, 4), 'big')
            client_pem_public = self.receive_all(client_socket, length_pub).decode('utf-8')
            client_public_key = serialization.load_pem_public_key(client_pem_public.encode(), default_backend())
            
            # Entschlüssle den symmetrischen Schlüssel
            symmetric_key = self.server_rsa_private_key.decrypt(
                encrypted_key,
                padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
            
            # Speichere die Verbindung im connection_pool
            with self.lock:
                if conn_id in self.connection_pool:
                    self.connection_pool[conn_id].update({
                        'symmetric_key': symmetric_key,
                        'algorithm': algorithm,
                        'client_public_key': client_public_key
                    })
            
            # Hauptempfangsschleife
            while self.running and not self.shutting_down:
                try:
                    length_bytes = self.receive_all(client_socket, 4)
                    if not length_bytes:
                        self.update_ui(f"[DEBUG] Keine Länge empfangen von {conn_id}", "system")
                        break
                    length = int.from_bytes(length_bytes, 'big')
                    data = self.receive_all(client_socket, length)
                    if not data or len(data) < 2:
                        self.update_ui(f"[DEBUG] Ungültige Daten von {conn_id} (Länge: {len(data) if data else 'None'})", "system")
                        continue

                    # Nachrichtentyp und Payload trennen
                    msg_type = data[:2]
                    payload = data[2:]
                    
                    # Fallunterscheidung anhand des Nachrichtentyps:
                    if msg_type == b"AK":
                        # ACK für Key Rotation
                        with self.lock:
                            if conn_id in self.pending_acks:
                                self.pending_acks[conn_id].set()
                                self.update_ui(f"[SUCCESS] Key rotation ACK received for {conn_id}", "system")
                        continue

                    elif msg_type == b"SF":
                        # Dateiübertragung: Hole die Verbindung aus dem Pool
                        conn_info = self.connection_pool.get(conn_id)
                        if not conn_info:
                            continue
                        keys = [conn_info['symmetric_key']]
                        if conn_info.get('previous_symmetric_key'):
                            keys.append(conn_info['previous_symmetric_key'])
                        decrypted_data = self.decrypt_message(payload, keys, conn_info['algorithm'])
                        # Aufruf des Reassembly-Mechanismus mit msg_type SF
                        self.process_received_data(decrypted_data, "server", msg_type)
                        continue

                    elif msg_type == b"NM":
                        conn_info = self.connection_pool.get(conn_id)
                        if not conn_info:
                            continue
                        keys = [conn_info['symmetric_key']]
                        if conn_info.get('previous_symmetric_key'):
                            keys.append(conn_info['previous_symmetric_key'])
                        decrypted_data = self.decrypt_message(payload, keys, conn_info['algorithm'])
                        # Übergabe von msg_type NM an den Reassembly-Mechanismus
                        self.process_received_data(decrypted_data, "server", b"NM")
                        if decrypted_data == "HEARTBEAT":
                            continue

                    elif msg_type == b"HB":
                        conn_info = self.connection_pool.get(conn_id)
                        if not conn_info:
                            continue
                        keys = [conn_info['symmetric_key']]
                        if conn_info.get('previous_symmetric_key'):
                            keys.append(conn_info['previous_symmetric_key'])
                        decrypted_data = self.decrypt_message(payload, keys, conn_info['algorithm'])
                        if decrypted_data == "HEARTBEAT":
                            continue

                    else:
                        self.update_ui(f"[WARNING] Unbekannter Nachrichtentyp von {conn_id}: {msg_type}", "warning")
                        continue

                except socket.timeout:
                    continue
                except Exception as e:
                    self.update_ui(f"[ERROR] Connection error bei {conn_id}: {str(e)}", "error")
                    break

        except Exception as e:
            self.update_ui(f"[ERROR] Handle client error: {str(e)}", "error")
        finally:
            with self.lock:
                if conn_id in self.connection_pool:
                    try:
                        client_socket.close()
                    except:
                        pass
                    del self.connection_pool[conn_id]


    def start_client(self):
        try:
            ip = self.client_ip.get()
            base_port = int(self.client_port.get())
            num_conn = int(self.conn_selector.get())

            self.stop_client()

            for i in range(num_conn):
                port = base_port + i
                client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client_socket.connect((ip, port))
                client_socket.settimeout(self.config['timeout'])
                
                # Perform handshake
                length = int.from_bytes(self.receive_all(client_socket, 4), 'big')
                handshake_data = self.receive_all(client_socket, length).decode('utf-8')
                algorithm, pem_public = handshake_data.split(':', 1)
                server_public_key = serialization.load_pem_public_key(pem_public.encode(), default_backend())
                
                # Generate and send symmetric key and client's public key
                symmetric_key = os.urandom(32)
                encrypted_key = server_public_key.encrypt(
                    symmetric_key,
                    padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                )
                client_pem_public = self.client_rsa_public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode('utf-8')
                
                client_socket.send(len(encrypted_key).to_bytes(4, 'big') + encrypted_key)
                client_socket.send(len(client_pem_public).to_bytes(4, 'big') + client_pem_public.encode())
                
                self.client_sockets[port] = {
                    'socket': client_socket,
                    'symmetric_key': symmetric_key,
                    'algorithm': algorithm,
                    'previous_symmetric_key': None,
                    'decryption_success_count': 0  # Initialize the counter here
                }

            self.update_ui(f"[CLIENT] Connected to {ip}:{base_port}-{base_port+num_conn-1}", "system")
            threading.Thread(target=self.receive_messages, daemon=True).start()
            self.start_heartbeat()

        except Exception as e:
            self.show_error(f"Client error: {str(e)}")
         
    def split_message(self, msg, parts):
        n = len(msg)
        k, rem = divmod(n, parts)
        return [msg[i*k + min(i, rem):(i+1)*k + min(i+1, rem)] for i in range(parts)]

    def send_message(self):
        message = self.message_input.get()
        if not message:
            return

        try:
            with self.lock:
                if self.client_sockets:
                    target = list(self.client_sockets.items())
                    role = "client"
                elif self.connection_pool:
                    target = list(self.connection_pool.items())
                    role = "server"
                else:
                    self.update_ui("[ERROR] Not connected", "error")
                    return

                num_conn = len(target)
                if num_conn == 0:
                    self.update_ui("[ERROR] No active connections", "error")
                    return

                msg_id = secrets.randbelow(2**32)  # Eindeutige Nachricht-ID
                parts = self.split_message(message, num_conn)

                for idx, (key, sock_info) in enumerate(target):
                    if idx >= len(parts):
                        continue
                    part = parts[idx]
                    header = f"{idx}:{msg_id}:{len(parts)}"
                    full_message = f"{header}|{part}"
                    # Verschlüssle die Nachricht
                    encrypted_message = self.encrypt_message(full_message, sock_info['symmetric_key'], sock_info['algorithm'])
                    # Füge den Nachrichtentyp "NM" (Normal Message) hinzu
                    payload = b"NM" + encrypted_message
                    length = len(payload).to_bytes(4, 'big')
                    try:
                        sock_info['socket'].send(length + payload)
                    except Exception as e:
                        self.update_ui(f"[ERROR] Send failed to {key}: {str(e)}", "error")

            self.update_ui(f"{self.get_timestamp()} [SENT] {message} ({role.upper()})", "send")
            self.message_input.delete(0, tk.END)

        except Exception as e:
            self.show_error(f"Send error: {str(e)}")


    def send_file(self):
        # Dateiauswahldialog öffnen
        filepath = fd.askopenfilename(title="Select file to send")
        if not filepath:
            return  # Abbruch, falls keine Datei ausgewählt wurde

        try:
            # Datei im Binärmodus lesen und Base64 kodieren
            with open(filepath, "rb") as f:
                file_bytes = f.read()
            file_b64 = base64.b64encode(file_bytes).decode('utf-8')
            # Extrahiere den Dateinamen
            import os
            filename = os.path.basename(filepath)
            # Baue den Nachrichteninhalt zusammen
            file_message = f"FILE:{filename}:{file_b64}"
        except Exception as e:
            self.update_ui(f"[ERROR] Reading file failed: {str(e)}", "error")
            return

        try:
            with self.lock:
                if self.client_sockets:
                    target = list(self.client_sockets.items())
                    role = "CLIENT"
                elif self.connection_pool:
                    target = list(self.connection_pool.items())
                    role = "SERVER"
                else:
                    self.update_ui("[ERROR] Not connected", "error")
                    return

            num_conn = len(target)
            if num_conn == 0:
                self.update_ui("[ERROR] No active connections", "error")
                return

            msg_id = secrets.randbelow(2**32)  # Eindeutige Nachricht-ID
            parts = self.split_message(file_message, num_conn)

            for idx, (key, sock_info) in enumerate(target):
                if idx >= len(parts):
                    continue
                part = parts[idx]
                header = f"{idx}:{msg_id}:{len(parts)}"
                full_message = f"{header}|{part}"
                encrypted_message = self.encrypt_message(full_message, sock_info['symmetric_key'], sock_info['algorithm'])
                payload = b"SF" + encrypted_message  # Nachrichtentyp SF
                length_bytes = len(payload).to_bytes(4, 'big')
                try:
                    sock_info['socket'].send(length_bytes + payload)
                except Exception as e:
                    self.update_ui(f"[ERROR] Send file failed to {key}: {str(e)}", "error")

            self.update_ui(f"{self.get_timestamp()} [SENT] File '{filename}' ({role})", "send")
        except Exception as e:
            self.show_error(f"Send file error: {str(e)}")



    def encrypt_message(self, plaintext, key, algorithm):
        # Füge einen konstanten Marker ein
        magic = "MSG:"
        plaintext = magic + plaintext
        if algorithm == 'aes-256-cbc':
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            padder = sym_padding.PKCS7(128).padder()
            padded_data = padder.update(plaintext.encode()) + padder.finalize()
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            return iv + ciphertext
        elif algorithm == 'chacha20':
            nonce = os.urandom(16)
            cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(plaintext.encode())
            return nonce + ciphertext
        else:
            raise ValueError("Unsupported algorithm")


    def decrypt_message(self, ciphertext, keys, algorithm):
        """
        Versucht, die Nachricht zuerst mit dem neuen Schlüssel zu entschlüsseln,
        falls das fehlschlägt, wird der alte Schlüssel verwendet.
        """
        for key in keys:
            if key is None:
                continue
            try:
                return self._perform_decryption(ciphertext, key, algorithm)
            except Exception:
                continue  # Falls der Schlüssel falsch ist, probiere den nächsten

        # Falls keine Entschlüsselung funktioniert, zurückmelden
        self.update_ui("[ERROR] Decryption failed with all keys", "error")
        return None


    def _perform_decryption(self, ciphertext, key, algorithm):
        if algorithm == 'aes-256-cbc':
            iv = ciphertext[:16]
            ciphertext = ciphertext[16:]
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            unpadder = sym_padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        elif algorithm == 'chacha20':
            nonce = ciphertext[:16]
            ciphertext = ciphertext[16:]
            cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext)
        else:
            raise ValueError("Unsupported algorithm")
        
        decoded = plaintext.decode()
        # Prüfe, ob der Marker vorhanden ist
        magic = "MSG:"
        if not decoded.startswith(magic):
            raise ValueError("Invalid message marker")
        return decoded[len(magic):]  # entferne den Marker und liefere den eigentlichen Inhalt


    def check_connection_health(self):
        with self.lock:
            for conn_id, conn_info in list(self.connection_pool.items()):
                try:
                    conn_info['socket'].send(b"PING")
                except Exception as e:
                    self.update_ui(f"[WARNING] Connection {conn_id} seems unhealthy: {str(e)}", "warning")
                    self.cleanup_connection(conn_id)


    def process_received_data(self, data, source, msg_type=b"NM"):
        """
        Führt die Wiederzusammenführung fragmentierter Nachrichten durch.
        Verwendet als Schlüssel ein Tupel (msg_id, msg_type), sodass auch
        unterschiedliche Nachrichtentypen (z. B. NM vs. SF) getrennt gepuffert werden.
        """
        try:
            if not data or data == "HEARTBEAT":
                return

            if "|" not in data:
                raise ValueError("Invalid message format: missing '|'")
            header, content = data.split("|", 1)
            if header.count(":") != 2:
                raise ValueError("Invalid header format")
            
            part_index_str, msg_id_str, total_parts_str = header.split(":")
            if not (part_index_str.isdigit() and msg_id_str.isdigit() and total_parts_str.isdigit()):
                raise ValueError("Invalid header values")
            part_index = int(part_index_str)
            msg_id = int(msg_id_str)
            total_parts = int(total_parts_str)
            if total_parts > 50:
                raise ValueError("Total parts value too high")
            
            # Verwende einen zusammengesetzten Schlüssel (msg_id, msg_type)
            key = (msg_id, msg_type)
            with self.lock:
                if key not in self.message_buffer:
                    self.message_buffer[key] = {'parts': [None] * total_parts, 'timestamp': time.time()}
                if part_index >= total_parts:
                    raise ValueError("Invalid part index")
                self.message_buffer[key]['parts'][part_index] = content

                if all(part is not None for part in self.message_buffer[key]['parts']):
                    full_message = "".join(self.message_buffer[key]['parts'])
                    if msg_type == b"SF":
                        # Bei Dateinachrichten: erwarte Format "FILE:{filename}:{base64_data}"
                        if full_message.startswith("FILE:"):
                            parts = full_message.split(":", 2)
                            if len(parts) < 3:
                                raise ValueError("Invalid file message format")
                            filename = parts[1]
                            file_b64 = parts[2]
                            file_bytes = base64.b64decode(file_b64)
                            with open(filename, "wb") as f:
                                f.write(file_bytes)
                            self.update_ui(f"[INFO] File '{filename}' received and saved", "system")
                        else:
                            self.update_ui("[ERROR] Reassembled file message missing FILE: marker", "error")
                    else:
                        timestamp = self.get_timestamp()
                        self.update_ui(f"{timestamp} [RECEIVED] {full_message}", "receive")
                    del self.message_buffer[key]
        except ValueError as e:
            self.update_ui(f"[WARNING] Ignored malformed message: {str(e)}", "warning")


    def start_heartbeat(self):
        def heartbeat_check():
            while self.running and not self.shutting_down:
                all_synced = True
                with self.lock:
                    for conn_id, conn_info in list(self.connection_pool.items()):
                        try:
                            current_key = conn_info.get('symmetric_key')
                            prev_key = conn_info.get('previous_symmetric_key')

                            # Falls beide Schlüssel vorhanden sind und unterschiedlich – Hinweis ausgeben
                            if current_key and prev_key and current_key != prev_key:
                                self.update_ui(f"[WARNING] Port {conn_id} might be out of sync", "warning")
                                all_synced = False

                            # Verschlüssele den Heartbeat
                            encrypted_hb = self.encrypt_message("HEARTBEAT", current_key, conn_info['algorithm'])
                            # Voranstellen des Nachrichtentyps "HB"
                            payload = b"HB" + encrypted_hb
                            conn_info['socket'].send(len(payload).to_bytes(4, 'big') + payload)

                        except Exception as e:
                            self.cleanup_connection(conn_id)

                if all_synced:
                    self.update_ui("[INFO] All ports are synchronized", "system")

                time.sleep(self.config['heartbeat_interval'])

        self.heartbeat_thread = threading.Thread(target=heartbeat_check, daemon=True)
        self.heartbeat_thread.start()


    def cleanup_dead_connections(self):
        dead_conns = []
        with self.lock:
            current_connections = list(self.connection_pool.items())
        
        for conn_id, sock in current_connections:
            try:
                sock.send(b"PING")
            except:
                dead_conns.append(conn_id)
        
        with self.lock:
            for conn_id in dead_conns:
                try:
                    self.connection_pool[conn_id].close()
                except:
                    pass
                del self.connection_pool[conn_id]

        dead_ports = []
        with self.lock:
            current_client_ports = list(self.client_sockets.keys())
        
        for port in current_client_ports:
            try:
                self.client_sockets[port].send(b"PING")
            except:
                dead_ports.append(port)
        
        with self.lock:
            for port in dead_ports:
                try:
                    self.client_sockets[port].close()
                except:
                    pass
                del self.client_sockets[port]

        if dead_conns or dead_ports:
            self.update_ui(f"{self.get_timestamp()} [SYSTEM] Cleaned {len(dead_conns)+len(dead_ports)} dead connections", "system")

    def cleanup_message_buffer(self):
        current_time = time.time()
        with self.lock:
            to_delete = []
            for msg_id, entry in self.message_buffer.items():
                if current_time - entry['timestamp'] > self.config['message_timeout']:
                    to_delete.append(msg_id)
            
            for msg_id in to_delete:
                del self.message_buffer[msg_id]
            if to_delete:
                self.update_ui(f"{self.get_timestamp()} [SYSTEM] Cleaned {len(to_delete)} stale messages", "system")

    def cleanup_connection(self, conn_id):
        with self.lock:
            if conn_id in self.connection_pool:
                try:
                    self.connection_pool[conn_id]['socket'].close()
                except:
                    pass
                del self.connection_pool[conn_id]

    def cleanup_client(self, port):
        with self.lock:
            if port in self.client_sockets:
                try:
                    self.client_sockets[port]['socket'].close()
                except:
                    pass
                del self.client_sockets[port]

    def update_ui(self, message, msg_type=None):
        self.message_box.config(state='normal')
        tag = {
            "send": "send",
            "receive": "receive",
            "error": "error",
            "system": "system"
        }.get(msg_type)
        self.message_box.insert(tk.END, message + "\n", tag)
        self.message_box.config(state='disabled')
        self.message_box.see(tk.END)

    def show_error(self, message):
        messagebox.showerror("Error", message)

    def get_timestamp(self):
        return datetime.datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")

    def on_close(self):
        self.shutting_down = True
        self.running = False
        
        with self.lock:
            for sock in self.server_sockets:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                    sock.close()
                except:
                    pass
            
            for sock in self.client_sockets.values():
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                    sock.close()
                except:
                    pass
        
        time.sleep(1)
        self.root.destroy()

    def stop_server(self):
        with self.lock:
            for sock in self.server_sockets:
                try:
                    sock.close()
                except:
                    pass
            self.server_sockets.clear()

    def stop_client(self):
        with self.lock:
            for sock in self.client_sockets.values():
                try:
                    sock.close()
                except:
                    pass
            self.client_sockets.clear()

if __name__ == "__main__":
    root = tk.Tk()
    app = EnhancedMultiConnectionApp(root)
    root.mainloop()
