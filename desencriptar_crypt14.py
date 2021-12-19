# 19/12/2021 esto funciona para encriptar y desencriptar
# No se ha probado con dbcrypt para antes de mayo 2021

from Crypto.Cipher import AES
import os
import sys
import zlib

def decrypt14(db_file, key_file, path):
    try:
        """ Esta funcion funciona para dbcrypt posterior a mayo de 2021 """
        if os.path.getsize(key_file) != 158:
            quit('[e] The specified input key file is invalid.')

        with open(key_file, "rb") as fh:
            key_data = fh.read()
            fh.seek(126)            # El inicio de la llave esta en la posicion 126 y son 32 bits
            key = fh.read(32)       # Leemos los 32 bits que representa la clave
            
        with open(db_file, "rb") as fh:
            file_size = os.path.getsize(db_file) 
            read_bites=file_size-191
            fh.seek(191)                    
            data = fh.read(read_bites)  # La base de datos encriptada empiez en la poscion 91 y va hasta el final del archivo
            fh.seek(67)                 # La seguna llave que esta dentro de la base de datos encriptada empieza en la posicion 67
            iv = fh.read(16)            # La segunda llave (nonce) tiene 16 bits, por lo que leemos 16 bits
            aes = AES.new(key, mode=AES.MODE_GCM, nonce=iv)

        with open(path, "wb") as fh:
            fh.write(zlib.decompress(aes.decrypt(data)))
        
        print("[-] " + db_file + " decrypted, '" + path + "' created")
        
    except Exception as e:
        print("[e] An error has ocurred encrypting '" + db_file + "' - ", e)

def encrypt14(db_file, key_file, db_cript, output):
    """ Funcion para encriptar base de datos en el formato crypt14 posterior a mayo 2021"""
    try:
        with open(key_file, "rb") as fh:
            key_data = fh.read()

        key = key_data[126:]
        with open(db_cript, "rb") as fh:
            db_cript_data = fh.read()

        header = db_cript_data[0:191]
        iv = db_cript_data[67:83]
        footer = db_cript_data[-20:]
        with open(db_file, "rb") as fh:
            data = fh.read()

        aes = AES.new(key, mode=AES.MODE_GCM, nonce=iv)
        with open(output, "wb") as fh:
            fh.write(header + aes.encrypt(zlib.compress(data)) + footer)
          
        print("[-] " + db_file + " encrypted, '" + output + "' created")

    except Exception as e:
        print("[e] An error has ocurred encrypting '" + db_file + "' - ", e)


if __name__ == "__main__":
    # encrypt14( "msgstore.db","key","msgstore.db.crypt14","msgstore1.db.crypt14")
    decrypt14( "msgstore1.db.crypt14", "key","msgstore2.db")
    
