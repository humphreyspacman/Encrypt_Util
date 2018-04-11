#!/usr/bin/python3.6

from Crypto.Cipher import AES
import hashlib
import os
from threading import Thread
from Crypto import Random
from optparse import OptionParser
import signal
import getpass

def handle_sig(sig,frame):
    #TODO
    print("dKJWIDWE")
    exit(0)
def encrypt(key,pathname):
    #TODO
    """Encrypt files"""
    dirname,filename = os.path.split(pathname)
    if not os.path.isfile(pathname):
        print("[!]File: {} not found".format(pathname))
        exit(0)
    if not os.access(pathname,os.R_OK):
        print("[!]Access denied")
        exit(0)
    chunksize = 64*1024
    outputFile = "(encrypted)"+filename
    filesize = str(os.path.getsize(pathname)).zfill(16)
    IV = Random.new().read(16)
    encryptor = AES.new(key,AES.MODE_CBC,IV)
    with open(pathname,'rb') as infile:
        with open(os.path.join(dirname,'{}'.format(outputFile)),'wb') as output:
            output.write(filesize.encode('utf-8'))
            output.write(IV)
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                elif len(chunk)%16 !=0:
                    chunk += b' '*(16 - (len(chunk)%16))
                output.write(encryptor.encrypt(chunk))
    print("Removing file: {}".format(filename))
    os.remove(pathname)
def decrypt(key,pathname):
    #TODO
    dirname,filename = os.path.split(pathname)
    """Decrypt encrypted file"""
    if not os.path.isfile(pathname):
        print("[!]File not found")
        exit(0)
    chunksize = 64*1024
    outputfile = filename[11:]
    with open(pathname,'rb') as infile:
        filesize = int(infile.read(16))
        IV  = infile.read(16)
        decryptor = AES.new(key,AES.MODE_CBC,IV)
        try:
            with open(os.path.join(dirname,outputfile),'wb') as output:
                while True:
                       chunk = infile.read(chunksize)
                       if len(chunk) == 0:
                               break
                       output.write(decryptor.decrypt(chunk))
                       output.truncate(filesize)
        except PermissionError as e:
            print("Permission Error:",e)
            print("[*]Run as root")
            exit(0)
    print("Removing file: {}".format(filename))
    os.remove(pathname)
def getKey(key):
    #TODO
    """"Generate hash from key(text)"""
    print("[*]Generating key...")
    hasher = hashlib.sha256()
    hasher.update(key.encode())

    return hasher.digest()
def encrypt_dir(key,dirname):
    #TODO
    """Encrypt files recursively"""
    if not os.path.isdir(dirname):
        print("[!]{} not a directory".format(dirname))
        print("[*]Set encrypt_dir as choice instead")
        exit(0)
    for pathname,_,filenames in os.walk(dirname):
        print("[*]Encrypting {}...".format(pathname))
        for file in filenames:
            if file == 'encrypt.py':
                continue
            print("[*]Encryping {}".format(pathname))
            worker = Thread(target=encrypt,args=(key,os.path.join(pathname,file),))
            worker.start()
    print("[*]Done encrypting files from {}".format(dirname))
    os.rename(dirname,"(encrypted){}".format(dirname))
def decrypt_dir(key,dirname):
    #TODO
    """Decrypt files recursively"""
    if not os.path.isdir(dirname):
        print("{} not a directory".format(dirname))
        print("[*]Set decrypt_dir as choice instead")
        exit(0)
    elif not dirname.startswith("(encrypted)"):
        print("[!]Files in directory not encrypted")
        exit(0)
    for pathname,_,filenames in os.walk(dirname):
        print("[*]Decrypting {}...".format(pathname))
        for file in filenames:
            worker = Thread(target=decrypt,args=(key,os.path.join(pathname,file),))
            worker.start()

    print("Done decrypting files from: {}".format(dirname))
    os.rename(dirname,dirname.replace("(encrypted)",""))

if __name__ == '__main__': 
    signal.signal(signal.SIGINT,handle_sig)
    choices = {'decrypt':decrypt,'encrypt':encrypt,'decrypt_dir':decrypt_dir,'encrypt_dir':encrypt_dir}
    parser = OptionParser(usage="encrypt.py -c choice -f pathname")
    parser.add_option('-c','--choice',type='string',dest='choice',action='store',help='encrypt,decrypt,encrypt_dir,decrypt_dir')
    parser.add_option('-p','--pathname',dest='pathname',type='string',action='store',help='specify the pathname of the file to encrypt or decrypt')
    option,args = parser.parse_args()
    if option.pathname == None or option.choice == None:
        print('Given less arguments')
        print(parser.usage)
        exit(0)
    else:
        if option.choice == 'encrypt' or option.choice == 'encrypt_dir':
            password = getpass.getpass("password: ")
            re_enter = getpass.getpass("Re-enter password: ")
            if password == '':
                print("[!]Password empty")
                exit(0)
            if password != re_enter:    
                print("[!]Do not match")
                exit(0)
        if option.choice == 'decrypt' or option.choice == 'decrypt_dir':
            password = getpass.getpass("password:")
        try:
            dirname,filename = os.path.split(option.pathname)
            os.chdir(dirname)
        except:
            filename = option.pathname
        if not filename.startswith('(encrypted)') and option.choice == 'decrypt':
            print("Cannot decrypt unencrypted file")
            exit(0)
        try:
            func = choices[option.choice]
        except:
            print("Invalid choice")
            exit(0)
        func(getKey(password),filename)
        print(":)")
