import socket
import struct
import ssl
import json
import time
import threading
from DES import Des
from RSA import RSA_Algorithm

Local_keys = ""
server_Keys = ""

class RSA_Container():
    def __init__(self) -> None:
        self.public_key: tuple[int, int] = None
        self.private_key: tuple[int, int] = None

class ClientProgram():
    def __init__(self) -> None:
        self.id             = ""
        self.host                = socket.gethostname()
        self.public_port         = 5022
        self.client_port         = 5023
        self.public_socket       = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket       = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.des_key: bytes      = '\0'
        self.server_ip           = ""
        self.server_port         = ""
        self.DES                 = Des()
        self.RSA                 = RSA_Algorithm()
        self.public_auth         = RSA_Container()
        self.local_RSA           = RSA_Container()
        self.client_RSA          = RSA_Container()
        self.ssl_context         = None
        self.lock                = threading.Lock()
        self.should_regenerate_des = False

    @staticmethod
    def pack_tuple(int_tuple: tuple[int, int]) -> bytes:
        return struct.pack('qq', *int_tuple) 

    @staticmethod
    def unpack_tuple(packed_data: bytes) -> tuple[int, int]:
        return struct.unpack('qq', packed_data)
    
    @staticmethod
    def pack_rsa(encrypted_message):
        return struct.pack(f'<{len(encrypted_message)}Q', *encrypted_message)

    @staticmethod
    def unpack_rsa(packed_message):
        num_integers = len(packed_message) // 8 
        return list(struct.unpack(f'<{num_integers}Q', packed_message))
    
    def __StartPublicAuthSocket(self):
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE 
        self.public_socket = self.ssl_context.wrap_socket(self.public_socket, server_hostname=self.host)
        
        self.public_socket.connect((self.host, self.public_port)) 
        self.server_ip, self.server_port = self.public_socket.getpeername()
        print(f"Connected to server at IP: {self.server_ip}, Port: {self.server_port}")

        # Additional Validation
        confirmation = input("Do you want to accept this server connection? (yes/no): ")
        if confirmation.lower() == 'no' :
            print("Connection Refused ! Terminating Connection ...")
            self.public_socket.close()
            return False
        else :
            print("Connection Accepted !\n")
            True

    def __StartClientSocket(self):
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE 
        self.client_socket = self.ssl_context.wrap_socket(self.client_socket, server_hostname=self.host)
        
        self.client_socket.connect((self.host, self.client_port)) 
        self.server_ip, self.server_port = self.client_socket.getpeername()
        print(f"Connected to server at IP: {self.server_ip}, Port: {self.server_port}")

        # Additional Validation
        confirmation = input("Do you want to accept this server connection? (yes/no): ")
        if confirmation.lower() == 'no' :
            print("Connection Refused ! Terminating Connection ...")
            self.client_socket.close()
            return False
        else :
            print("Connection Accepted !\n")
            True

    # New DES Key Every 1 Minute
    def __HanldeDesRegen(self):
        while True:
            time.sleep(60)
            self.lock.acquire()
            try:
                self.should_regenerate_des = True
            finally:
                self.lock.release()
            print("\nWarn: Should Regenerate DES Key Now")

            # Wait Until it's set back to false
            while True: 
                self.lock.acquire()
                try:
                    if self.should_regenerate_des == False:
                        time.sleep(0.1)
                        break
                finally:
                    self.lock.release()
                    time.sleep(4)
    
    def __ConstructMessage(self, message: str, type: str):
        payload = {
            'type': type,
            'message': message
        }
        return json.dumps(payload)
    
    def __HandleMessage(self):
        # Handle Incoming / Outgoing Message
        message = input(" -> ") 

        while message.strip() != 'bye':
            # Encrypt the string before send to server
            message = self.__ConstructMessage(message, 'MSG').encode('utf-8')  
            encrypted_message = self.DES.Encrypt(message, self.des_key)
            self.client_socket.send(encrypted_message) 

            # Listen to response
            data = self.client_socket.recv(3024)

            # Decrypt the encrypted message from server
            print('\nRaw from Client: ' + str(data))
            raw_msg = self.DES.Decrypt_using_key(data, self.des_key)
            msg = json.loads(raw_msg)
            
            print("decrypted from client: ", msg)
            print()

            self.lock.acquire()
            try:
                if self.should_regenerate_des == True:
                    self.should_regenerate_des = False
                    message = self.__ConstructMessage('Re-Generate DES', 'GENERATE').encode('utf-8')  
                    encrypted_message = self.DES.Encrypt(message, self.des_key)
                    self.client_socket.send(encrypted_message)

                    # Send DES Key
                    print("\nSending DES Key to Client B ....")
                    self.des_key = self.DES.Random_Bytes(8)

                    # Encrypt with our private key
                    encrypted_des = self.RSA.encrypt(self.des_key.hex(), self.local_RSA.private_key) 
                    # Encrypt with Client B public key
                    encrypted_des = self.RSA.encrypt(self.pack_rsa(encrypted_des).hex(), self.client_RSA.public_key)
                    self.client_socket.send(self.pack_rsa(encrypted_des))

                    print(f"New DES Key: ", self.des_key, '\n')
            finally:
                self.lock.release()

            message = input(" -> ")

        self.client_socket.close()
        self.public_socket.close()

    def Start(self):
        if self.__StartPublicAuthSocket() == False:
            return
        
        # Receive Server RSA keys from server
        print("Waiting for Public Authority to send it's RSA Public Key...")
        server_data = self.public_socket.recv(3024)
        self.public_auth.public_key = self.unpack_tuple(server_data)
        print(f"Public Authority - Public Key : ", self.public_auth.public_key, '\n')

        # Send our RSA Keys to Public Authority Server
        print("Register our Public key to Public Authority Server....")
        self.local_RSA.public_key, self.local_RSA.private_key = self.RSA.generate_keypair()
        self.public_socket.send(self.pack_tuple(self.local_RSA.public_key))        

        print(f"Local RSA - Public Key : ", self.local_RSA.public_key)
        print(f"Local RSA - Private Key: ", self.local_RSA.private_key, '\n')

        # Set our ID identity
        self.id = self.public_socket.recv(3024).decode()
        print(f"Our Identity: ", self.id, "\n")

        # Wait for Client B & Request it's public key from Public Authority
        print("Requesting client B public key .....")
        payload = {
        "type": "REQUEST_PUBLIC_KEY",
        "id": "B",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")  
        }

        self.public_socket.sendall(json.dumps(payload).encode('utf-8'))

        response = self.public_socket.recv(3024)
        response = self.unpack_rsa(response)
        response_json = json.loads(self.RSA.decrypt(response, self.public_auth.public_key))
        self.client_RSA.public_key = self.unpack_tuple(bytes.fromhex(response_json['public_key']))
        print(f"Public Authority Response: ", response_json)
        print(f"Client B - Public Key: ", self.client_RSA.public_key, '\n')

        # Make client connection
        if self.__StartClientSocket() == False:
            return
        
        # Send Our Identifier (IDa) and Nonce (N1) to client B
        N1 = self.DES.Random_Bytes(8).hex()
        payload = {
            "type": "STEP_3",
            "id": "A",
            "N1": N1
        }

        message = self.RSA.encrypt(json.dumps(payload), self.client_RSA.public_key)
        self.client_socket.send(self.pack_rsa(message))
        print(f"Data sent to client - B :", json.dumps(payload))
        print(f"encrypted:", self.pack_rsa(message), "\n")

        # Wait for client B message
        print("Getting response from client B ....")
        b_message = self.client_socket.recv(3024)
        message = self.unpack_rsa(b_message)
        message_json = json.loads(self.RSA.decrypt(message, self.local_RSA.private_key))
        print(message_json)

        if(message_json['N1'] != N1):
            print("Invalid Nonce N1")
            return
        
        N2 = message_json['N2']
        final_payload = {
            "type": "STEP_7",
            "id": "A",
            "N2": N2
        }

        # Send a message again to client B
        message = self.RSA.encrypt(json.dumps(final_payload), self.client_RSA.public_key)
        self.client_socket.send(self.pack_rsa(message))

        # Send DES Key
        print(f"\nData sent to client - B :", json.dumps(final_payload))
        print("\nSending DES Key to Client B ....")
        self.des_key = self.DES.Random_Bytes(8)

        # Encrypt with our private key
        encrypted_des = self.RSA.encrypt(self.des_key.hex(), self.local_RSA.private_key) 
        # Encrypt with Client B public key
        encrypted_des = self.RSA.encrypt(self.pack_rsa(encrypted_des).hex(), self.client_RSA.public_key)
        self.client_socket.send(self.pack_rsa(encrypted_des))

        print(f"DES Key: ", self.des_key, '\n')

        thread = threading.Thread(target=self.__HanldeDesRegen, daemon=True)
        thread.start()

        # Handle Encrypted Communication
        self.__HandleMessage()


if __name__ == '__main__':
    Program = ClientProgram()
    Program.Start()
    


# Keys are distributed and exchange using secure RSA Keys

# 1. Client send keys -> Server receive keys
# 2. Server send keys -> Client receive key

# 1. Client encrypt -> Server Decrypt
# 2. Server Encrypt -> Client Decrypt