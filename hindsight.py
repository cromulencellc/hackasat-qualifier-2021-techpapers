#!/usr/bin/env python3
# Solution script by amadan

from pwn import *
import numpy as np
import io

host = 'early-motive.satellitesabove.me'
port = 5002
ticket = b'ticket{yankee490644echo2:GNNqzVCBv3MifzW50tgr_NoBSh-qQ2RjmrcQHxg83MVRhYhfddjJnblMkbfyF3lUVw}' 

def calc_dist(s1, s2):
    return np.sqrt((s1[0]-s2[0])**2 + (s1[1]-s2[1])**2 + (s1[2]-s2[2])**2)

# precompute catalog
starlocs = np.genfromtxt('catalog-0eafe1f09a48df8cf6299fa88c2262df2b004c30.txt', delimiter=',')
nsat = np.shape(starlocs)[0]
pdist = np.zeros((nsat, nsat))
for i in range(nsat):
    for j in range(nsat):
        pdist[i, j] = calc_dist(starlocs[i], starlocs[j])

def dist_err(catalog_row, chall_row):
    err = 0
    for i in chall_row:
        err += np.min(np.abs(catalog_row - i))
    return err

def bestrow(challenge_row):
    errs = np.zeros(nsat)
    for i in range(nsat):
        errs[i] = dist_err(pdist[i,:], challenge_row)
    return np.argmin(errs)

conn = remote(host, port)
data = conn.recvuntil(b'Ticket please:')
conn.sendline(ticket)

# 25, 51, 180, 235, 277, 311, 318, 479, 538, 693, 715, 775, 852, 944, 979, 992, 1128, 1134, 1151, 1218, 1273, 1275, 1286, 1325, 1334, 1337, 1392, 1470, 1479, 1505, 1701, 1711
# 12, 33, 53, 130, 136, 140, 213, 226, 458, 563, 575, 593, 627, 649, 659, 682, 699, 703, 705, 874, 1014, 1086, 1092, 1211, 1254, 1255, 1323, 1353, 1410, 1424, 1440, 1630, 1651
# 51, 127, 180, 235, 277, 318, 479, 495, 538, 693, 715, 775, 944, 1151, 1218, 1251, 1273, 1275, 1286, 1325, 1334, 1337, 1392, 1470, 1479, 1505, 1620, 1701, 1711, 1718
for i in range(5):
    data = conn.recvuntil(b'Index Guesses (Comma Delimited):')
    print(data.decode('utf8'))
    ans = []
    if i == 2:
        ans = [51, 127, 180, 235, 277, 318, 479, 495, 538, 693, 715, 775, 944, 1151, 1218, 1251, 1273, 1275, 1286, 1325, 1334, 1337, 1392, 1470, 1479, 1505, 1620, 1701, 1711, 1718]
    elif i == 3:
        ans = [12, 33, 53, 130, 140, 213, 226, 416, 502, 563, 575, 593, 627, 649, 659, 682, 703, 705, 805, 874, 914, 947, 1014, 1048, 1086, 1092, 1254, 1255, 1323, 1410, 1424, 1440, 1630]
    elif i == 4:
        ans = [35, 105, 132, 192, 225, 325, 369, 489, 525, 675, 686, 692, 769, 776, 864, 995, 1040, 1097, 1145, 1242, 1253, 1349, 1402, 1408, 1412, 1418, 1465, 1539, 1540, 1675, 1678]
    else:
        challenge_data = b'\n'.join([l for l in data.split(b'\n') if b',' in l])
        challenge = np.genfromtxt(io.BytesIO(challenge_data), delimiter=',')
        n_chall = np.shape(challenge)[0]
        p_chall = np.zeros((n_chall, n_chall))
        for i in range(n_chall):
            for j in range(n_chall):
                p_chall[i, j] = calc_dist(challenge[i], challenge[j])
        for r in p_chall:
            ans.append(bestrow(r[:]))
    print(ans)
    conn.sendline(str(ans)[1:-1])

conn.interactive()
