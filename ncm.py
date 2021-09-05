# 依赖pycrypto库
import binascii
import struct
import base64
import json
import os
import sys
import shutil
from Crypto.Cipher import AES


def main():
    base_dir = os.path.dirname(__file__)
    ncm_dir = os.path.join(base_dir, 'ncm')
    if not os.path.exists(ncm_dir):
        print('文件夹不存在: %s' % (os.path.abspath(ncm_dir),))
        return
    print('开始转换ncm')
    output_dir = os.path.join(base_dir, 'out')
    print('文件读取目录: %s' % (os.path.abspath(ncm_dir),))
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    for root, dirs, files in os.walk(ncm_dir):
        for file in files:
            file_path = os.path.join(root, file)
            if file.endswith('.ncm'):
                print('开始转换文件: %s' % (file_path,))
                dump(file_path, output_dir)
            elif file.endswith('.flac') or file.endswith('.mp3'):
                print('复制无需转换: %s' % (file_path,))
                shutil.copyfile(file_path, os.path.join(output_dir, file))
    print('转换完成')
    print('文件保存目录: %s' % (os.path.abspath(output_dir),))


def dump(file_path, output_path):
    core_key = binascii.a2b_hex("687A4852416D736F356B496E62617857")
    meta_key = binascii.a2b_hex("2331346C6A6B5F215C5D2630553C2728")
    unpad = lambda s : s[0:-(s[-1] if type(s[-1]) == int else ord(s[-1]))]
    with open(file_path, 'rb') as file:
        header = file.read(8)
        assert binascii.b2a_hex(header) == b'4354454e4644414d'
        file.seek(2, 1)
        key_length = file.read(4)
        key_length = struct.unpack('<I', bytes(key_length))[0]
        key_data = file.read(key_length)
        key_data_array = bytearray(key_data)
        for i in range (0,len(key_data_array)): key_data_array[i] ^= 0x64
        key_data = bytes(key_data_array)
        cryptor = AES.new(core_key, AES.MODE_ECB)
        key_data = unpad(cryptor.decrypt(key_data))[17:]
        key_length = len(key_data)
        key_data = bytearray(key_data)
        key_box = bytearray(range(256))
        c = 0
        last_byte = 0
        key_offset = 0
        for i in range(256):
            swap = key_box[i]
            c = (swap + last_byte + key_data[key_offset]) & 0xff
            key_offset += 1
            if key_offset >= key_length: key_offset = 0
            key_box[i] = key_box[c]
            key_box[c] = swap
            last_byte = c
        meta_length = file.read(4)
        meta_length = struct.unpack('<I', bytes(meta_length))[0]
        meta_data = file.read(meta_length)
        meta_data_array = bytearray(meta_data)
        for i in range(0,len(meta_data_array)): meta_data_array[i] ^= 0x63
        meta_data = bytes(meta_data_array)
        meta_data = base64.b64decode(meta_data[22:])
        cryptor = AES.new(meta_key, AES.MODE_ECB)
        meta_data = unpad(cryptor.decrypt(meta_data)).decode('utf-8')[6:]
        meta_data = json.loads(meta_data)
        crc32 = file.read(4)
        crc32 = struct.unpack('<I', bytes(crc32))[0]
        file.seek(5, 1)
        image_size = file.read(4)
        image_size = struct.unpack('<I', bytes(image_size))[0]
        image_data = file.read(image_size)
        file_name = '%s.%s' % (os.path.splitext(os.path.basename(file_path))[0], meta_data['format'])
        with open(os.path.join(output_path, file_name), 'wb') as music:
            chunk = bytearray()
            while True:
                chunk = bytearray(file.read(0x8000))
                chunk_length = len(chunk)
                if not chunk:
                    break
                for i in range(1,chunk_length+1):
                    j = i & 0xff;
                    chunk[i-1] ^= key_box[(key_box[j] + key_box[(key_box[j] + j) & 0xff]) & 0xff]
                music.write(chunk)


if __name__ == '__main__':
    main()
