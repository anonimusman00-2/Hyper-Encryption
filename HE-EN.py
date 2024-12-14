import base64  
import hashlib  
import secrets  
import time  
import zlib  
import os  
import json  
import sys  
from typing import Dict, Any  
from cryptography.hazmat.primitives import hashes, padding  
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC  
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  
from cryptography.hazmat.backends import default_backend  

# Set window title  
if os.name == 'nt':  # for Windows  
    os.system('title Hyper Encryption')  
else:  # for other systems  
    print("\033]0;Hyper Encryption\007")  

class UltraHiperEncryption:  
    def __init__(self, master_key: str):  
        # Master key normalization  
        self.master_key_str = str(master_key)  
        
        # Multi-Layer Security Initiation  
        self.initiation_time = time.time()  
        
        # Security Component Generator  
        self.salt = self._generate_salt_complex()  
        
        # Primary Key Derivation  
        self.symmetric_key = self._derive_symmetric_key()  
        
        # Static HMAC Key  
        self.hmac_key = self._generate_hmac_key()  
    
    def _generate_salt_complex(self) -> bytes:  
        """  
        High entropy multi-component salt generator  
        """  
        return hashlib.sha3_512(  
            self.master_key_str.encode() +   
            str(self.initiation_time).encode() +   
            secrets.token_bytes(128)  
        ).digest()  
    
    def _derive_symmetric_key(self) -> bytes:  
        """  
        Multi-layer symmetric key derivation with extreme complexity  
        """  
        # Primary Key with High Iterations  
        kdf = PBKDF2HMAC(  
            algorithm=hashes.SHA3_512(),  
            length=32,  # AES-256 standard  
            salt=self.salt,  
            iterations=10000000  # High iterations  
        )  
        
        # Complex key input  
        input_key = hashlib.sha3_512(  
            self.master_key_str.encode() +   
            self.salt +   
            str(self.initiation_time).encode()  
        ).digest()  
        
        return kdf.derive(input_key)  
    
    def _generate_hmac_key(self) -> bytes:  
        """  
        Multi-component HMAC key generation with deterministic approach  
        """  
        return hashlib.sha3_512(  
            hashlib.sha3_512(self.master_key_str.encode()).digest() +   
            self.salt +   
            hashlib.sha3_512(str(self.initiation_time).encode()).digest()  
        ).digest()  
    
    def encryption_ultra(self, data: str) -> Dict[str, Any]:  
        """  
        Multi-layer encryption with comprehensive defense  
        """  
        try:  
            # Compress data   
            compress_data = zlib.compress(data.encode('utf-8'), level=9)  
            
            # Padding   
            padder = padding.PKCS7(algorithms.AES.block_size).padder()  
            data_pad = padder.update(compress_data) + padder.finalize()  
            
            # AES-256 Encryption GCM Mode  
            iv = secrets.token_bytes(16)  
            cipher = Cipher(  
                algorithms.AES(self.symmetric_key),   
                modes.GCM(iv),  
                backend=default_backend()  
            )  
            enkriptor = cipher.encryptor()  
            
            # Data encryption  
            encrypted_data = enkriptor.update(data_pad) + enkriptor.finalize()  
            tag = enkriptor.tag  
            
            # Ultra Secure Payload  
            payload = {  
                'encryption': base64.b85encode(encrypted_data).decode(),  
                'iv': base64.b85encode(iv).decode(),  
                'tag': base64.b85encode(tag).decode(),  
                'salt': base64.b85encode(self.salt).decode(),  
                'hmac': base64.b85encode(self.hmac_key).decode(),  
                'timestamp': self.initiation_time,  
                'initial_length': len(data),  
                'hash_integrity': hashlib.sha3_512(compress_data).hexdigest(),  
                'algorithm_version': '1.0'  # Add algorithm version  
            }  
            
            return payload  
        
        except Exception as e:  
            return {"error": f"Encryption Failed: {str(e)}"}  
    
    def decrypt_ultra(self, payload: Dict[str, Any], master_key: str) -> str:  
        """  
        Multi-layer decryption with strict validation  
        """  
        try:  
            # Validate payload structure  
            required_keys = ['encryption', 'iv', 'tag', 'salt', 'timestamp']  
            for key in required_keys:  
                if key not in payload:  
                    raise ValueError(f"Missing required key: {key}")  
            
            # Master key normalization  
            master_key_str = str(master_key)  
            
            # Decode payload  
            data_encryption = base64.b85decode(payload['encryption'])  
            iv = base64.b85decode(payload['iv'])  
            tag = base64.b85decode(payload['tag'])  
            salt = base64.b85decode(payload['salt'])  
            
            # Reconstruct key with same payload parameters  
            payload_time = payload['timestamp']  
            
            # Re-Derivation of Key with Original Salt  
            kdf = PBKDF2HMAC(  
                algorithm=hashes.SHA3_512(),  
                length=32,  
                salt=salt,  
                iterations=10000000  
            )  
            
            # Input key identical to encryption  
            input_key = hashlib.sha3_512(  
                master_key_str.encode() +   
                salt +   
                str(payload_time).encode()  
            ).digest()  
            
            symmetric_key = kdf.derive(input_key)  
            
            # AES-GCM Decryption  
            cipher = Cipher(  
                algorithms.AES(symmetric_key),   
                modes.GCM(iv, tag),  
                backend=default_backend()  
            )  
            dekriptor = cipher.decryptor()  
            raw_data = dekriptor.update(data_encryption) + dekriptor.finalize()  
            
            # Unpadding  
            unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()  
            data_unpad = unpadder.update(raw_data) + unpadder.finalize()  
            
            # Decompress  
            data_decompress = zlib.decompress(data_unpad)  
            
            return data_decompress.decode('utf-8')  
        
        except Exception as e:  
            return f"Decryption Failed: {str(e)}"  

# The input_payload and main functions remain the same as before.  
def input_payload():  
    """  
    Function for gradual and safe payload input  
    """  
    print("\n---Input Payload Encryption ---")  
    print("Payload Input Instructions:")  
    print("1. Enter the complete JSON payload")  
    print("2. Press Enter 2 times to complete input")  
    print("3. Make sure the JSON format is valid\n")  
    
    payload_lines = []  
    print("Start inputting payload (Press Enter 2 times to finish):")  
    while True:  
        line = input()  
        if line == "":  
            # If Enter is empty twice, complete input  
            if len(payload_lines) > 0:  
                break  
            else:  
                print("Input payload cannot be empty. Please try again.")  
                continue  
        payload_lines.append(line)  
    
    # Merge payload lines  
    payload_str = "\n".join(payload_lines)  
    
    try:  
        # Try parsing JSON  
        payload = json.loads(payload_str)  
        return payload  
    except json.JSONDecodeError:  
        print("\nError: Invalid JSON format!")  
        return None  

def input_message_multiline():  
    """  
    Multiline message input function with enter limitation  
    """  
    print("\nEnter Message (Press Enter 4 times to complete input):")  
    message_lines = []  
    enter_count = 0  
    
    while True:  
        line = input()  
        
        # If the line is empty  
        if line == "":  
            enter_count += 1  
            
            # If you have entered 5 times (4 times empty), complete the input  
            if enter_count == 3:  
                break  
        else:  
            # Reset enter count if there is a non-blank input  
            enter_count = 0  
        
        # Add rows to list  
        message_lines.append(line)  
    
    # Merge message lines  
    message = "\n".join(message_lines)  
    
    return message  

def save_decrypted_message(decrypted_message):  
    """  
    Save decrypted message with filename validation  
    """  
    try:  
        # Input filename with validation  
        while True:  
            filename = input("Enter the file name to save the message (e.g.: secret_message.txt): ").strip()  
            
            # Add .txt extension if not present  
            if not filename.lower().endswith('.txt'):  
                filename += '.txt'  
            
            # Check filename validity  
            if filename and all(char not in filename for char in ['/', '\\', ':', '*', '?', '"', '<', '>', '|']):  
                break  
            else:  
                print("Invalid filename. Please use valid characters.")  
        
        # Save file directly  
        with open(filename, 'w', encoding='utf-8') as f:  
            f.write(decrypted_message)  
        print(f"Message successfully saved to {filename}")  
    
    except Exception as e:  
        print(f"Error saving file: {e}")

def main():  
    while True:  
        # Main course  
        print("\n--- Ultra Hyper Encryption ---")  
        print("1. Encrypt Message")  
        print("2. Decrypt Message")  
        print("3. Exit")  
        
        # User Choice  
        choice = input("Enter options: ").strip()  
        
        if choice == '1':  
            try:  
                # Master Key Input  
                master_key = input("Enter Master Key (minimum 16 characters): ")  
                if len(master_key) < 16:  
                    print("Key too short! Minimum 16 characters.")  
                    continue  
                
                # Multiline Message Input  
                message = input_message_multiline()  
                
                # Message validation  
                if not message.strip():  
                    print("Message cannot be empty!")  
                    continue  
                
                # Show process message  
                print("\nEncrypting message...")  
                
                # Create Encryption Object  
                enkriptor = UltraHiperEncryption(master_key)  
                
                # Message Encryption  
                encryption_result = enkriptor.encryption_ultra(message)  
                
                # Check for encryption error  
                if 'error' in encryption_result:  
                    print(encryption_result['error'])  
                    continue  
                
                # Show Encrypted Payload  
                print("\n--- Encrypted Payload ---")  
                payload_str = json.dumps(encryption_result, indent=2)  
                print(payload_str)  
                
                # Save to File Optional  
                save = input("\nSave payload to file? (y/n): ").lower()  
                if save == 'y':  
                    name_file = input("Enter file name (example: secret_message.json): ")  
                    
                    # Message to save file  
                    print("\nSaving payload...")  
                    
                    with open(name_file, 'w') as f:  
                        f.write(payload_str)  
                    
                    print(f"Payload saved in {name_file}")  
            
            except Exception as e:  
                print(f"Error occurred: {e}")  
        
        elif choice == '2':  
            try:  
                # Select Payload Source  
                source = input("Select payload source (1. Enter Manually, 2. Read from File): ")  
                
                if source == '1':  
                    # Manual Payload Input  
                    print("\nValidating payload...")  
                    
                    payload = input_payload()  
                    
                    if payload is None:  
                        continue  
                
                elif source == '2':  
                    # Read from File  
                    name_file = input("Enter payload file name: ")  
                    
                    # Message reading file  
                    print("\nReading payload file...")  
                    
                    try:  
                        with open(name_file, 'r') as f:  
                            payload = json.load(f)  
                    
                    except FileNotFoundError:  
                        print(f"File {name_file} not found!")  
                        continue  
                    except json.JSONDecodeError:  
                        print(f"The JSON format in {name_file} is invalid!")  
                        continue  
                
                else:  
                    print("Invalid choice!")  
                    continue  
                
                # Master Key Input  
                master_key = input("Enter Master Key for Decryption: ")  
                
                # Message Decryption  
                print("\nDecrypting message...")  
                
                # Message Decryption  
                decrypted_message = UltraHiperEncryption(master_key).decrypt_ultra(payload, master_key)  
                
                # Check for decryption error  
                if decrypted_message.startswith("Decryption Failed:"):  
                    print(decrypted_message)  
                    continue  
                
                # Show Results  
                print("\n--- Decrypted Message ---")  
                print(decrypted_message)  
                
                # Save Message Option  
                while True:  
                    save = input("\nDo you want to save the decrypted message? (y/n): ").lower().strip()  
                    
                    if save == 'y':  
                        # Message to save file  
                        print("\nSaving message...")  
                        
                        save_decrypted_message(decrypted_message)   
                        break  
                    elif save == 'n':  
                        print("Message not saved.")  
                        break  
                    else:  
                        print("Invalid choice. Please enter 'y' or 'n'.")  
            
            except Exception as e:  
                print(f"Decryption Error Occurred: {e}")  
        
        elif choice == '3':  
            # Exit the Program  
            print("Thank you. Exit the program.")  
            break  
        
        else:  
            print("Invalid choice. Please try again.")  

if __name__ == "__main__":  
    main()