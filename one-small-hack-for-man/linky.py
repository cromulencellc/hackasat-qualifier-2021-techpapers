#!/usr/bin/env python3
# Solution script by amadan

from pwn import *
import numpy as np

host = 'wild-wish.satellitesabove.me'
port = 5022
ticket = b'ticket{charlie829650delta2:GF0nJdVsUXo_TUYBl6nFJ8-7AAtcbsrLTLRLoFscDlt_XdFh15DLL3zP1H_l5DpaLw}'

conn = remote(host, port)
data = conn.recvuntil(b'Ticket please:')
conn.sendline(ticket)

data = conn.recvuntil(b'Calculate and provide the recieve antenna gain in dBi')
gain = 10*np.log10(0.55*(np.pi*5.3/0.025)**2)
conn.sendline(b'53.87')

data = conn.recvuntil(b'Calculate and provide the ground terminal G/T (dB/K)')
conn.sendline('24.69')

data = conn.recvuntil(b'Determine the transmit power (in W) to achieve 10dB of Eb/No margin (above minimum for BER):')

ebn0 = 14.4
data_rate = 10000000.0
tx_loss = -1 - 1.74
tx_gain = 16.23
fspl = -221.84
path_loss = fspl #- 0.5 - 2.1 - 0.1
rx_gain = 53.87
rx_loss = -2 - 2 - 4.48
temp = 522
ct_boltz = 1.379 * pow(10, -23)
bw = data_rate / np.log2(1 + ebn0)
noise = 10 * np.log10(ct_boltz * temp * bw)
pt = ebn0 - tx_loss - tx_gain - path_loss - rx_gain - rx_loss + noise
PWatts = '{:.4f}'.format(10**((pt-30)/10))
print(PWatts)
conn.sendline(PWatts)

conn.interactive()
