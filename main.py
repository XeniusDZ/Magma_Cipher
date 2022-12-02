
class magma:
    def __init__(self,message,key):
        self.message = message
        self.key = key
        self.SBOX = [["0xF","0xC","0x2","0xA","0x6","0x4","0x5","0x0","0x7","0x9","0xE","0xD","0x1","0xB","0x8","0x3"],
                     ["0xB","0x6","0x3","0x4","0xC","0xF","0xE","0x2","0x7","0xD","0x8","0x0","0x5","0xA","0x9","0x1"],
                     ["0x1","0xC","0xB","0x0","0xF","0xE","0x6","0x5","0xA","0xD","0x4","0x8","0x9","0x3","0x7","0x2"],
                     ["0x1","0x5","0xE","0xC","0xA","0x7","0x0","0xD","0x6","0x2","0xB","0x4","0x9","0x3","0xF","0x8"],
                     ["0x0","0xC","0x8","0x9","0xD","0x2","0xA","0xB","0x7","0x3","0x6","0x5","0x4","0xE","0xF","0x1"],
                     ["0x8","0x0","0xF","0x3","0x2","0x5","0xE","0xB","0x1","0xA","0x4","0x7","0xC","0x9","0xD","0x6"],
                     ["0x3","0x0","0x6","0xF","0x1","0xE","0x9","0x2","0xD","0x8","0xC","0x4","0xB","0xA","0x5","0x7"],
                     ["0x1","0xA","0x6","0x8","0xF","0xB","0x0","0x4","0xC","0x3","0x5","0x9","0x7","0xD","0x2","0xE"]]
    def convert_to_asii(self,message):
        string = ""
        for char in message:
            a = str(format(ord(char), 'b')).zfill(8)
            string += a
        return self.slice_to_blocks(string)
    def slice_to_blocks(self,message):
        arr = []
        for i in range(0,len(message),64):
            part = message[i:i + 64]
            part.ljust(64,"0")
            arr.append(part)
        return arr
    def round_key(self):
        key = ""
        keys = []
        for element in self.key:
            a = format(ord(element), 'b').zfill(8)
            key += a
        for i in range(0,len(key),32):
            keys.append(key[i:i+32])
        return keys

    def encrypt(self,array):
        string = ""
        for block in array:
            while len(block) <64:
                block += "0"
            keys = self.round_key()
            N1 = block[0:32]
            N2 = block[32:]
            print(N1,N2)
            l = 0
            o = 1
            for round in range(4):
                l += 1
                if l == 4:
                    keys = keys[::-1]
                for key in keys:
                    print( str(o) + str(keys) )
                    o +=1
                    before_N1 = N1
                    N1 = format((int(N1,2)+int(key,2))%(2**32),'b').zfill(32)
                    Split_N1 = [N1[x:x+4] for x in range(0,len(N1),4)]
                    for i in range(len(Split_N1)):
                        k = int(Split_N1[i],2)
                        Split_N1[i] = format(int(self.SBOX[i][k],16),"b").zfill(4)
                    Split_N1 = list("".join(Split_N1).zfill(32))
                    bits_11 = Split_N1[0:11]
                    Split_N1 = Split_N1[-21:]+bits_11
                    Split_N1 = "".join(Split_N1)
                    N1,N2 = format((int(Split_N1,2)^int(N2,2)),'b').zfill(32),before_N1
            plus = str(N1)+str(N2)
            for j in range(0,len(plus),8):
                string += chr(int(plus[j:j+8],2))
        return string
    def decrypt(self,array):
        string = ""
        for block in array:
            while len(block) < 64:
                block += "0"
            keys = self.round_key()
            N1 = block[0:32]
            N2 = block[32:]
            l = 0
            for round in range(4):
                l += 1
                if l == 2:
                    keys = keys[::-1]
                print(keys)
                for key in keys:
                    before_N1 = N1
                    N1 = format((int(N1,2)+int(key,2))%(2**32),'b').zfill(32)
                    Split_N1 = [N1[x:x+4] for x in range(0,len(N1),4)]
                    for i in range(len(Split_N1)):
                        k = int(Split_N1[i],2)
                        Split_N1[i] = format(int(self.SBOX[i][k],16),"b").zfill(4)
                    Split_N1 = list("".join(Split_N1).zfill(32))
                    bits_11 = Split_N1[0:11]
                    Split_N1 = Split_N1[-21:]+bits_11
                    Split_N1 = "".join(Split_N1)
                    N1,N2 = format((int(Split_N1,2)^int(N2,2)),'b').zfill(32),before_N1
            plus = str(N1) + str(N2)
            for j in range(0, len(plus), 8):
                string += chr(int(plus[j:j + 8], 2))
        return string
lol = magma("lmaolmaolmaolmao","azertyuiopqsdfghjklmwxcvbnazerty")
encrypted =lol.encrypt(lol.convert_to_asii(lol.message))
decrypted = lol.decrypt(lol.convert_to_asii(encrypted))
print(encrypted)
print(decrypted)
