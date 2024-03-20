from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from PIL import Image
import binascii

# Function to encrypt data using AES CBC mode
def encrypt_data(data, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(data.encode(), AES.block_size)
    ciphertext = cipher.encrypt(padded_data)
    return ciphertext

# Function to decrypt data using AES CBC mode
def decrypt_data(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(ciphertext)
    unpadded_data = unpad(decrypted_data, AES.block_size)
    return unpadded_data.decode()

# Pixels are modified according to the
# 8-bit binary data and finally returned
def modPix(pix, data, key, iv):
    encrypted_data = encrypt_data(data, key, iv)
    data_bits = ''.join(format(x, '08b') for x in encrypted_data)
    imdata = iter(pix)

    for i in range(len(data_bits)):
        pixel = [value for value in imdata.__next__()[:3]]

        # Pixel value should be made
        # odd for 1 and even for 0
        if (data_bits[i] == '0' and pixel[0] % 2 != 0):
            pixel[0] -= 1
        elif (data_bits[i] == '1' and pixel[0] % 2 == 0):
            if(pixel[0] != 0):
                pixel[0] -= 1
            else:
                pixel[0] += 1

        yield tuple(pixel)

def encode_enc(newimg, data, key, iv):
    w = newimg.size[0]
    (x, y) = (0, 0)
    for pixel in modPix(newimg.getdata(), data, key, iv):
        # Putting modified pixels in the new image
        newimg.putpixel((x, y), pixel)
        if (x == w - 1):
            x = 0
            y += 1
        else:
            x += 1

# Encode data into image
def encode():
    img = input("Enter image name(with extension) : ")
    image = Image.open(img, 'r')
    image.show()

    data = input("Enter data to be encoded : ")
    key = input("Enter AES key (16 characters in hexadecimal): ").ljust(16, '0')[:16]  # Adjust key length
    iv = input("Enter IV (16 bytes in hexadecimal): ").ljust(16, '0')[:16]  # Adjust IV length
    if len(data) == 0:
        raise ValueError('Data is empty')

    newimg = image.copy()
    encode_enc(newimg, data, binascii.unhexlify(key), binascii.unhexlify(iv))

    new_img_name = input("Enter the name of new image(with extension) : ")
    newimg.save(new_img_name, str(new_img_name.split(".")[1].upper()))

from Crypto.Util.Padding import unpad

# Decode the data in the image
def decode():
    img = input("Enter image name(with extension) : ")
    image = Image.open(img, 'r')

    data_bits = ''
    imgdata = iter(image.getdata())

    while True:
        pixels = [value for value in imgdata.__next__()[:3]]

        # Extracting LSB of each pixel value
        for i in pixels:
            if (i % 2 == 0):
                data_bits += '0'
            else:
                data_bits += '1'

        # Check if we've reached the end of the data (8 zeroes)
        if data_bits.endswith('00000000'):
            break

    # Convert binary data back to plaintext
    key = input("Enter AES key (16 characters in hexadecimal): ").ljust(32, '0')[:32]  # Pad with zeros if too short, truncate if too long
    iv = input("Enter IV (16 bytes in hexadecimal): ").ljust(32, '0')[:32]  # Pad with zeros if too short, truncate if too long
    decrypted_data = decrypt_data(bytes(int(data_bits[i:i + 8], 2) for i in range(0, len(data_bits), 8)), binascii.unhexlify(key), binascii.unhexlify(iv))
    decrypted_data = unpad(decrypted_data, 16)  # Remove padding
    return decrypted_data.decode('utf-8')  # Decode bytes to string

# Main Function
def incript():
    a = int(input(":: Welcome to Steganography ::\n"
                  "1. Encode\n2. Decode\n"))
    if a == 1:
        encode()
    elif a == 2:
        print("Decoded Word :  " + decode())
    else:
        raise Exception("Enter correct input")

incript()
