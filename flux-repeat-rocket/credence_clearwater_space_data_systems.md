# Credence Clearwater Space Data Systems
We are provided with a file containing floats in text form looking like this:
```
-0.7478157631961678+0.6802927868274203j
-0.6841016205795244+0.7480324209995708j
-0.4862116283376359+0.6601658463080996j
-1.012560333188981+0.7788565722570056j
-0.7859559691332394-0.33925823782872466j
-0.5974771411348444-0.6148395466972645j
-0.7282318233660728-0.7287714797613187j
-0.7235452186145177-0.6875360569507909j
0.7423468473738213-0.8031189410767087j
```
The first step is to convert these floats into binary form so that we can process them with GNU Radio. For this we used the following python script:

```python
import struct

f = open("./iqdata.txt", "r")
lines = f.readlines()
nums = []
for l in lines:
    split = 0
    for i, c in enumerate(l):
        if i == 0:
            continue
        if c == '-' or c == '+':
            split = i
            break
    nums.append(float(l[:split]))
    nums.append(float(l[split:-2]))
```

Opening the data in GNU Radio and plotting it on a constellation sink resulted in the following:

![](res/constellation.png)

Thus, the data is modulated using some form of QPSK. Using this information to demodulate the data resulted in the same value four times in a row. This means, that there are 4 samples per symbol. To fully demodulate the signal we used the following pipeline:

![](res/gnuradio.png)

The remaining work was simply guessing parameters (DQPSK vs QPSK, Endianness, mapping). To automate this, we wrote a simple python script that enumerated the mapping from quadrant to symbol and tried the other parameters by hand. To detect the correct solution we searched for the hex string `0x1acf` which is the beginning of the synchronization marker accoring to [CCSDS 131.0-B-3](res/131x0b3e1.pdf). 

```python
import binascii

file = open("./decoded", "rb")
symbols = file.read()

def to_binstr(input, offset):
    bitstr = ""
    for b in input:
        b = (offset + b) % 4
        if b == 0:
            bitstr += "00"
        elif b == 1:
            bitstr += "01"
        elif b == 2:
            bitstr += "10"
        elif b == 3:
            bitstr += "11"
    return bitstr

def to_hexstr(binstr):
    bytestr = int(binstr, 2).to_bytes(len(binstr)//8, byteorder="big")
    return binascii.b2a_hex(bytestr)

for i in range(4):
    print(i)
    symbols_bin = to_binstr(symbols, i)
    hexstr = to_hexstr(symbols_bin)
    print(hexstr)
    print(b'1acf' in hexstr)
```

This yielded exactly one configuration with the following decoded message:
```
  Offset: 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 	
00000000: 1A CF FC 1D 00 01 C0 00 00 6F 66 6C 61 67 7B 68    .O|...@..oflag{h
00000010: 6F 74 65 6C 38 32 36 33 35 32 6A 75 6C 69 65 74    otel826352juliet
00000020: 32 3A 47 4E 70 36 45 72 71 79 30 4D 52 4A 41 61    2:GNp6Erqy0MRJAa
00000030: 46 6A 50 43 4D 6C 45 52 69 2D 46 75 35 62 2D 77    FjPCMlERi-Fu5b-w
00000040: 5F 5F 34 70 67 33 4E 4D 5A 30 52 4E 6E 63 79 79    __4pg3NMZ0RNncyy
00000050: 64 6D 36 66 2D 6A 33 6C 69 32 47 69 56 79 55 64    dm6f-j3li2GiVyUd
00000060: 59 36 61 30 6C 73 37 6D 5A 46 4C 77 68 64 61 71    Y6a0ls7mZFLwhdaq
00000070: 47 69 62 41 30 4B 61 59 6B 7D                      GibA0KaYk}
```