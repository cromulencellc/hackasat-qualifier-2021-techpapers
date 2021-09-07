import numpy as np
from telnetlib import Telnet

with open("catalog-0eafe1f09a48df8cf6299fa88c2262df2b004c30.txt") as f:
    txt = [  [ float(val) for val in i.split(",\t") ] for i in filter(lambda a: a.strip() != "", f.readlines()) ] 

# testvals = [
#     [ 0.063510,       0.172198,       0.983013 ],
#     [ 0.099288,       -0.176080,      0.979356 ],
#     [ -0.055440,      -0.154325,      0.986464 ],
#     [ 0.125521,       -0.002894,      0.992087 ],
#     [ -0.218239,      -0.067029,      0.973591 ],
#     [ -0.018649,      0.063052,       0.997836 ],
#     [ -0.074830,      0.156673,       0.984812 ],
#     [ -0.035332,      0.072418,       0.996748 ],
#     [ 0.083429,       -0.177233,      0.980626 ],
#     [ 0.123108,       -0.155649,      0.980111 ],
#     [ 0.026359,       0.127270,       0.991518 ],
#     [ -0.172270,      -0.002115,      0.985048 ],
#     [ 0.095199,       0.003956,       0.995450 ],
#     [ -0.061920,      0.246842,       0.967076 ],
#     [ -0.165385,      -0.058480,      0.984494 ],
#     [ -0.158970,      -0.110085,      0.981127 ],
#     [ -0.164970,      0.059348,       0.984511 ],
#     [ -0.046028,      -0.223992,      0.973503 ],
#     [ 0.020075,       -0.010497,      0.999743 ],
#     [ -0.030429,      -0.254281,      0.966652 ],
#     [ 0.035188,       -0.125803,      0.991431 ],
#     [ 0.104716,       -0.053336,      0.993071 ],
#     [ 0.143662,       0.069087,       0.987212 ],
#     [ -0.006348,      -0.233888,      0.972243 ],
#     [ -0.121062,      -0.123531,      0.984928 ],
#     [ 0.235419,       -0.009800,      0.971845 ],
#     [ -0.130585,      -0.010126,      0.991385 ],
#     [ 0.111752,       -0.184471,      0.976464 ],
#     [ 0.064663,       0.160371,       0.984936 ],
#     [ 0.108471,       0.068876,       0.991711 ],
# ]

catalog = np.array( txt )
catalog = np.divide( np.array( catalog ), np.sum(catalog**2, axis = 1, keepdims=True) )
print(catalog.shape)
# testvals = np.array( testvals )
# testvals = np.divide( np.array( testvals ), np.sum(testvals**2, axis = 1, keepdims=True) )
# print(testvals.shape)



catalog_angles = np.matmul(catalog, catalog.transpose())
# testval_angles = np.matmul(testvals, testvals.transpose())


CATALOG_LEN = catalog_angles.shape[0]
ERROR_THRESH = 0.0005

def test_val(guesses):
    # print(len(guesses), guesses)
    solutions = []
    for test_idx in range(CATALOG_LEN):
        if test_idx in guesses:
            continue
        
        if sum([abs( catalog_angles[guess, test_idx] - testval_angles[ len(guesses), guess_idx ] ) for guess_idx, guess in enumerate(guesses) ]) < ERROR_THRESH * len(guesses):

            next_guesses = guesses + [ test_idx ]
            if len(next_guesses) >= testval_angles.shape[1]:
                return [ next_guesses ]
            
            #print(next_guesses)
            solutions += test_val(next_guesses)
    
    return solutions

# for start_idx in range(CATALOG_LEN):
#     guess = [ start_idx ]
#     res = test_val(guess)
#     if res != []:
#         print(res)

def test():
    for start_idx in range(CATALOG_LEN):
        guess = [ start_idx ]
        res = test_val(guess)
        if res != []:
            print(res)
            return res

# 25, 51, 180, 235, 277, 311, 318, 479, 538, 693, 715, 775, 852, 944, 979, 992, 1128, 1134, 1151, 1218, 1273, 1275, 1286, 1325, 1334, 1337, 1392, 1470, 1479, 1505, 1701, 1711
# 12, 33, 53, 130, 136, 140, 213, 226, 458, 563, 575, 593, 627, 649, 659, 682, 699, 703, 705, 874, 1014, 1086, 1092, 1211, 1254, 1255, 1323, 1353, 1410, 1424, 1440, 1630, 1651

with Telnet( "early-motive.satellitesabove.me", 5002) as tn:
    tn.read_until(b"please:\n")
    tn.write(b"ticket{whiskey65795tango2:GD69RsTs54vMK5B14BL6CT8c837QlXDb6_NJcEAI3zI2ZeMfEf_x4A_z4_EEo3YRaQ}\n")

    for i in range(5):
        print(i)
        testvals = []
        while True:
            line = tn.read_until(b"\n").strip().decode()
            if line == "":
                break
            testvals.append([ float(val.strip()) for val in line.split(",") ])

        testvals = np.array( testvals )
        testvals = np.divide( np.array( testvals ), np.sum(testvals**2, axis = 1, keepdims=True) )

        testvals = np.array( testvals )
        testvals = np.divide( np.array( testvals ), np.sum(testvals**2, axis = 1, keepdims=True) )

        testval_angles = np.matmul(testvals, testvals.transpose())

        tn.read_until(b"):\n")
        res = test()
        if res is None:
            print("MATCH FAILED for ", testvals)
            raise Exception()

        tn.write(', '.join([ str(val) for val in res[0]] ).encode() + b"\n")
        print(tn.read_until(b"\n"))

    print(tn.read_until(b"\n"))
    while True:
        buf = b""
        bytes_read = tn.read_some()
        buf += bytes_read
        if bytes_read == b"":
            break
    
    print(buf.decode())