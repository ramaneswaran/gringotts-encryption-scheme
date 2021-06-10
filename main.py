import hmac
import ast
import hashlib
import pprint
import Cryptodome
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.PublicKey import ECC
from Cryptodome import Random
from Cryptodome.Cipher import PKCS1_OAEP

pp = pprint.PrettyPrinter(indent=4)

AES_KEY = get_random_bytes(16)

def get_key_pair():
  """
  Returns RSA private and public key
  """
  random_generator = Random.new().read
  key = RSA.generate(1024, random_generator)
  private_key = RSA.import_key(key.export_key(format='PEM'))
  public_key = RSA.import_key(key.public_key().export_key(format='PEM'))

  return {'private_key': private_key, 'public_key':public_key}

class Client:

  def __init__(self, id: int, session_pub_key: Cryptodome.PublicKey.RSA.RsaKey):

    self.client_id = id
    self.master_key = get_random_bytes(16)

    client_key = get_key_pair()

    self.client_public_key = client_key['public_key'] 
    self.client_private_key = client_key['private_key']


    self.session_pub_key = session_pub_key 

    self.receiver_id = None
    self.nonce = None
    self.session_key = None
  
  @property
  def get_client_id(self):
    return self.client_id

  @property
  def get_client_public_key(self):
    return self.client_public_key 
  
  @property
  def get_master_key(self):
    return self.master_key
  
  def intiate_session(self, receiver_id):
    """
    Initiate a session by registering with session manager
    """

    try:

      self.receiver_id = receiver_id
      self.session_key = None 
      self.nonce = get_random_bytes(16)

      encryptor = PKCS1_OAEP.new(self.session_pub_key)

      enc_nonce = encryptor.encrypt(nonce)

      return enc_nonce
    
    except Exception as error:
      print(repr(error))

  def set_session_details(self, payload):

    try:

      decryptor = PKCS1_OAEP.new(self.client_private_key)
      
      self.session_key = decryptor.decrypt(payload['session_key'])
      self.client_key = decryptor.decrypt(payload['client_key'])

      # if 'nonce' in payload:
      #   self.nonce = decryptor.decrypt(payload['nonce'])

    except Exception as error:
      print(repr(error))

  def send_message(self,message: bytes):
    """
    Sends a message to client with id->receiver_id
    """


    try:
      e_cipher = AES.new(AES_KEY, AES.MODE_EAX)
      ciphertext = e_cipher.encrypt(message)


      digest = hmac.new(b'secret', b'msg', hashlib.sha1).digest()
      
      payload = {'ciphertext': ciphertext, 'digest': digest, 
                 'sender_id': self.client_id, 'receiver_id': self.receiver_id, 
                 'cipher_nonce': e_cipher.nonce}

      return payload

    except Exception as error:
      print(repr(error))


  def receive_message(self, data):
    """
    Recives a message by parsing data 
    """
    
    try:
      
      ciphertext = data['ciphertext']
      digest = data['digest']
      cipher_nonce = data['cipher_nonce']

      d_cipher = AES.new(AES_KEY, AES.MODE_EAX, cipher_nonce)
      message = d_cipher.decrypt(ciphertext)

      return message

    except Exception as error:
      print(repr(error))
  
  def get_register_details(self):
    """
    Returns details to register with session manager
    """

    try:

        encryptor = PKCS1_OAEP.new(self.session_pub_key)
        
        payload = dict()

 
        payload['master_key'] = encryptor.encrypt(self.master_key)
        payload['client_id'] = self.client_id
        payload['client_public_key'] = self.client_public_key

        return payload


    except Exception as error:
      print(repr(error))


class SessionManager:

  def __init__(self):

    self.session_table = dict()
    
    self.blacklist = set()
    
    self.master_keys = dict()

    self.public_keys = dict()

    manager_key = get_key_pair()

    self.manager_public_key = manager_key['public_key'] 
    self.manager_private_key = manager_key['private_key']

  @property
  def get_public_key(self):
    """
    Returns public key
    """

    return self.manager_public_key
  
  def register_client(self, client_id: int, master_key: bytes, public_key):
    """
    Registers a client
    """

    try:

      decryptor = PKCS1_OAEP.new(self.manager_private_key)
      master_key = decryptor.decrypt(master_key)
      client_id = client_id
      public_key = public_key

      self.master_keys[client_id] = master_key
      self.public_keys[client_id] = public_key 

    except Exception as error:
      print(repr(error))


  def register_session(self, sender_id: int, receiver_id: int, nonce: bytes):
    """
    Creates a new session for (sender_id, receiver_id) for 
    """

    try:

      if sender_id in self.blacklist:
        raise Exception(f"{sender_id} is blacklisted")
      
      elif receiver_id in self.blacklist:
        raise Exception(f"{receiver_id} is blacklisted")


      else:
      
        decryptor = PKCS1_OAEP.new(self.manager_private_key)

        
        nonce = decryptor.decrypt(nonce)

        session_key = get_random_bytes(16)

        data = {'nonce':nonce, 'session_key': session_key}

        self.session_table[(sender_id, receiver_id)] = data    

        encryptor = PKCS1_OAEP.new(self.public_keys[sender_id])
        
        payload = dict()

        payload['session_key'] = encryptor.encrypt(data['session_key'])
        payload['client_key'] = encryptor.encrypt(self.master_keys[receiver_id])

        return payload

    except Exception as error:
      print(repr(error))

  def get_session_details(self, sender_id: int, receiver_id: int):
    """
    Authenticate session by checking (sender_id, receiver_id) against session_table
    """

    try:

      if sender_id in self.blacklist:
        raise Exception(f"{sender_id} is blacklisted")

      session = (sender_id, reciever_id)
      if session in self.session_table:

        data = self.session_table[session]

        encryptor = PKCS1_OAEP.new(self.public_keys[receiver_id])
        
        payload = dict()

        payload['nonce'] = encryptor.encrypt(data['nonce'])
        payload['session_key'] = encryptor.encrypt(data['session_key'])
        payload['client_key'] = encryptor.encrypt(self.master_keys[sender_id])

        return payload

      else:

        raise Exception(f"Session not registered")
      
      return False

    except Exception as error:
      print(repr(error))

  def revoke_client_access(self, client_id: int):
    """ 
    Adds a client to blacklist
    """

    try:

      self.blacklist.add(client_id)
      return True 

    except Exception as error:
      print(repr(error))

  def redeem_client_access(self, client_id: int):
    """
    Removes client from blacklist
    """

    try:
      self.blacklist.remove(client_id)
      return True

    except Exception as error:
      print(repr(error))


if __name__ == "__main___":
    # Example of message transfer in normal conditions

        # Setup
        session_manager = SessionManager()

        A = Client(id=123, session_pub_key=session_manager.get_public_key)
        B = Client(id=456, session_pub_key=session_manager.get_public_key)

        Ad = A.get_register_details()
        Bd = B.get_register_details()

        session_manager.register_client(Ad['client_id'], Ad['master_key'], Ad['client_public_key'])
        session_manager.register_client(Bd['client_id'], Bd['master_key'], Bd['client_public_key'])

        # nonce = A.intiate_session(Bd['client_id'])
        # payload = session_manager.register_session(Ad['client_id'], Bd['client_id'], nonce)

        # A.set_session_details(payload)

        payload = A.send_message(b'secret message')
        print("[INFO] Payload is:")
        pp.pprint(payload)





        message = B.receive_message(payload)
        print("Decrypted message is")
        print(message)