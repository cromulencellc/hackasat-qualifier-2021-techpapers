











![](3D"SingleEventUpsetQualsTechnicalPaper_files/image002.png")  
  







Qual= ification Event Technical Paper











SingleEventU= pset

  



The following 5 write-ups were assembled by the Hack-a= -Sat2 2021 team
SingleEventUpset.

Table of Contents

[Hack-a-Sat2 Qualif= ier 2021:� credence clearwater space d= ata systems.
4](3D"#_Toc77153027")=

[Hack-a-Sat2 Qualifier 2021:� Take Out the Trash. 9](3D"#_T=)=

[Hack-a-Sat2 Qualifier 2021:� groundead. 15](3D"#_T=)=

[Hack-a-Sat2 Qualifier 2021:� Fiddlin' John Carson. 18](3D"#_T=)=

[Hack-a-Sat2 Qualifier 2021:� Cotton Eye GEO.. 20](3D"#_T=)=

 <= /o:p>



  



# Hack-a-Sat2 Qualifier 2021:� credence clearwater space data systems<= /a>

  
**Category** :� We're On the Same Wavelength

**Points: � 155

**Solves: � 21

**Description:**

We've captured this noisy IQ data from a satellite and= need to decode it.
Figure out how to filter the noise while maintaining the sign= al
characteristics, then demodulate and decode the signal to get the flag. The
satellite is transmitting using asynchronous markers in CCSDS space packets=
and an unknown modulation.

**Files:**

�        [https://generated.2021.hackasat.com/noise/noise-
romeo411892zulu2.tar=
.bz2](3D"https://generated.2021.hackasat.com/noise/noise-romeo411892zulu2.ta=)

## Write-up

_By Jason, part of the SingleEventUpset team_

The chall= enge provides one file: noise-romeo411892zulu2.tar.bz2 which is a
bzip2 compress= ed tarball archive. _The challenge is self-contained �= with
the flag residing in the demodulated data decoded as ASCII characters._ =

## Analysis

Extractin= g the file with standard file archive utilities (e.g., 7zip) yields
a single directory containing the file iqdata.txt. Viewing the file iqdata.txt
in a = text editor shows that it contains plaintext floating-point complex in-
phase and quadrature (I/Q) samples in the format ivalue+qvaluej<= /span>,
which can be directly read into many signal processing and analysis tools or
scripting languages. GNU Octave is used to process the data in this solutio=
n.

Viewing t= he power spectral density (shown in Figure 1) indicates that the
captured I/Q data is likely a variant of phase shift key= ing (PSK) or minimum
shift keying (MSK). Given that the problem statement refer= s to the CCSDS
standard, Quadrature Phase Shift Keying (QPSK) is the most likely candidate
and is used as a starting point for the analysis. Both standard Q= PSK and
differential QPSK (DQPSK) are analyzed.

We plot a= n eye diagram to get an estimate of the oversampling ratio (OSR)
also referred to= as the number of samples per symbol (SPS). The SPS can be
any positive fractional/rational number, but to provide sufficient
synchronization fidel= ity and keep hardware complexity low, most
communications systems use a whole number (often a power of two) value for the
SPS that is greater than or equ= al to four. The eye diagram shown in Figure 2
confirms that the SPS for this signal capture is four and that the assumpti=
on of PSK or differential PSK (and not offset PSK or MSK) is likely correct
as= the I and Q eyes are aligned in time with no offset.

&nb;= sp;

![](3D"SingleEventUpsetQualsTechnicalPaper_files/image004.jpg")

Figure 1: Power Spectral Density of Capt= ured Signal



![](3D"SingleEventUpsetQualsTechnicalPaper_files/image006.jpg")

Figure 2: Eye Diagram of Captured Signal=

Given the integer oversample rate and lack of frequency error, by choosing an
appropriate starting sample it is possible = to demodulate the data simply by
decimating by a factor of four, taking the si= gn of both I and Q samples to
get hard decision bits, interleaving the resulti= ng I and Q hard decision
bits, and packing the bits into bytes before decoding t= hem as ASCII
characters. If the QPSK assumption is correct _and_ if there = is no forward
error correction coding applied to the data, then the remaining unknowns are
the constellation mapping and bit packing order. A QPSK (or DQ= PSK)
modulation type is confirmed by inspecting the constellation diagram shown =
in Figure 3.

![](3D"SingleEventUpsetQualsTechnicalPaper_files/image008.jpg")

Figure 3: Constellation Diagram of Captu= red Signal

The problem statement indicates that CCSDS frami= ng markers are present in
the demodulated data. From the CCSDS specification (= _TM SYNCHRONIZATION AND
CHANNEL CODING_ ) the base ASM marker is given as 0x1ACFFC1D for uncoded data,
convolutional, Reed-Solomon, concatenated, rate-7/8 LDPC for Transfer Frame,
and all LDPC with SMTF stream coded data.= If this ASM marker is found, then
the data _may_ be uncoded. If the data = is uncoded, then the demodulated data
can be directly mapped to ASCII to find the flag.= If a different CCSDS ASM
marker is found or if the demodulated data does not result in intelligible
ASCII characters, then the data is likely forward er= ror correction coded and
additional decoding would be necessary to extract the flag. The solution given
below starts from the assumption that the data is uncoded and performs a
brute-force search of possible starting samples, constellation mappings and
bit (2-bit dibit) to byte packing orders. The fl= ag is found using the above
assumptions (uncoded QPSK at four SPS), so no additional processing is
performed in this solution.

## Solu= tion

1.&n;= bsp;     Read in samples from the challenge file and = plot the power
spectral density and eye diagram for analysis. Use 4 samples per symbol based
on eye diagram.

2.&n;= bsp;     A delay-conjugate-multiply (DCM) operation is applied to
perform differential demodulation but is not needed. The DCM operation is
provided in the case that a standard QPSK demodulation did not= yield
intelligible results.

3.&n;= bsp;     Decimate the input samples by 4. Verify QPSK= (or DQPSK)
assumption by inspecting constellation diagram.

4.&n;= bsp;     Use GNU Octave�s built-in function �perms� to find all
permutations of a QPSK constellation (24 permutations found of the= vector [0,
1, 2, 3]).

5.&n;= bsp;     Loop over all constellation permutations. For each
permutation, loop over all decimated samples, generating two hard deci= sion
bits (dibits) of data per decimated symbol based on the sign (signum functi=
on) of the I and Q data. Append dibits to create a bit vector of all
demodulate= d, decoded data.

6.&n;= bsp;     For a given permutation, loop over starting sample indices to
find a sample index that results in a decodable ASM marke= r. Our solution
found a decodable ASM marker and ASCII string using sample zero (zero based
indexing) as the starting sample.

7.&n;= bsp;     For a given permutation, attempt to pack 2-b= it dibits into a
byte in possible orders (4 possible dibit packing orders). Se= arch each
constellation permutation and dibit byte packing order for the ASM mar= ker
0x1ACFFC1D

8.&n;= bsp;     Once a hit occurs for an ASM marker match, m= ap the bytes
after the marker to ASCII and complete the search.

9.&n;= bsp;     Print the ASCII characters found by the sear= ch and verify
that a valid flag is produced. Our solution found a constellation mapping of
[3, 0, 2, 1] and a direct dibit to byte packing (a byte contains dibits [0, 1,
2, 3] concatenated).

Here�s the solution script:

    
    
    #wotsw3
    
    
    =
    warning('off','all');
    
    
    close a=
    ll;
    
    
    );
    
    
    psdSig =3D abs(fftshift(fft(sig)));
    
    
    freqs =3D linspace(-Fs/2, Fs/2, length(psdSig));
    
    
    plot(freqs<=
    code>, psdS=
    ig);
    
    
    eyediagramsig, 8, 8);
    
    
    sps =3D 4;
    
    
    jj =3D 1;
    
    
    � dcm(jj) =3D sig(ii) .* conj(sig(ii-sps));
    
    
    � jj =3D jj + 1;
    
    
     
    
    
    asm =3D '1ACFFC1D';
    
    
    ordvec =3D perms([0 1=
     2 3]);
    
    
    stophere =3D 0;
    
    
    � % Inelegant way of making dibit=
    s
    
    
    � dibits =3D [];
    
    
    � for ii =3D 1:length(decimated)
    
    
    ��� if (real(decimated(ii)) > =
    0 && imag(decimated(ii)) > 0)<=
    /pre>
    
    
    ����� dibits =3D [dibits; de2bi=
    (ordvec(pskordering,1), 2)'];
    
    
    ��� elseif (real(decimated(ii)) &=
    lt; 0 && imag(decimated(ii)) > 0)<=
    /pre>
    
    
    ����� dibits =3D [dibits; de2bi=
    (ordvec(pskordering,2), 2)'];
    
    
    ��� elseif (real(decimated(ii)) &=
    lt; 0 && imag(decimated(ii)) < 0)<=
    /pre>
    
    
    ����� dibits =3D [dibits; de2bi=
    (ordvec(pskordering,3), 2)'];
    
    
    ��� else=
    
    
    
    ����� dibits =3D [dibits; de2bi=
    (ordvec(pskordering,4), 2)'];
    
    
    ��� end<=
    /pre>
    
    
    � end
    
    
    � for startidx =3D 1:200
    
    
    ��� tdibits =3D dibits(startidx:end);<=
    /span>
    
    
    ��� tdibits =3D =
    tdibits(1:8*floor(length(tdibits)=
    /8));
    
    
    ��� % 1st group=
    
    
    
    ��� bytes =3D reshape(tdibits, length(tdibits)/8, 8);
    
    
    ��� bytesint =3D bi2de(bytes);=
    
    
    
    ��� temp =3D dec2hex(bytesint);
    
    
    ��� temp2 =3D [];
    
    
    ��� for kk =3D 1:length(temp)
    
    
    ���� temp2 =3D [temp2 temp(kk, :)];
    
    
    ��� end<=
    /pre>
    
    
    ��� if (strfind(temp2, asm))
    
    
    ����� eng =3D char(bytesint);
    
    
    ����� stophere =3D 1;=
    
    
    
    ��� ��break;
    
    
    ��� end
    
    
    ��� % 2nd group=
    
    
    
    ��� bytes =3D reshape(tdibits, length(tdibits)/8, 8);
    
    
    ��� bytesint =3D bi2de(fliplr=
    (bytes));
    
    
    ��� temp =3D dec2hex(bytesint);
    
    
    ��� temp2 =3D [];
    
    
    ��� for kk =3D 1:length(temp)
    
    
    ���� temp2 =3D [temp2 temp(kk, :)];
    
    
    ��� end<=
    /pre>
    
    
    ��� if (strfind(temp2, asm))
    
    
    ����� eng =3D char(bytesint);
    
    
    ����� stophere =3D 1;=
    
    
    
    ����� break;
    
    
    ��� end
    
    
    ��� % 3rd group=
    
    
    
    ��� bytes =3D reshape(tdibits, 8, length=
    (tdibits)/8)';
    
    
    ��� bytesint =3D bi2de(bytes);=
    
    
    
    ��� temp =3D dec2hex(bytesint);
    
    
    ��� temp2 =3D [];
    
    
    ��� for kk =3D 1:length(temp)
    
    
    ���� temp2 =3D [temp2 temp(kk, :)];
    
    
    ��� end<=
    /pre>
    
    
    ��� if (strfind(temp2, asm))
    
    
    ����� eng =3D char(bytesint);
    
    
    ����� stophere =3D 1;=
    
    
    
    ����� break;
    
    
    ��� end
    
    
    ��� % 4th group=
    
    
    
    ��� bytes =3D reshape(tdibits, 8, length=
    (tdibits)/8)';
    
    
    ��� bytesint =3D bi2de(fliplr=
    (bytes));
    
    
    ��� temp =3D dec2hex(bytesint);
    
    
    ��� temp2 =3D [];
    
    
    ��� for kk =3D 1:length(temp)
    
    
    ���� temp2 =3D [temp2 temp(kk, :)];
    
    
    ��� end<=
    /pre>
    
    
    ��� if (strfind(temp2, asm))
    
    
    ����� eng =3D char(bytesint);
    
    
    ����� stophere =3D 1;=
    
    
    
    ����� break;
    
    
    ��� end
    
    
    ��� %eng =3D char(bytesint);
    
    
    � end
    
    
    � if (stophere)
    
    
    ��� break;
    
    
    � end
    
    
    eng =3D eng(11:end).';

` `

Running the script results in the flag:

    
    
    flag{romeo411892zulu2:GCJSuvoUNCfNac5IhmMbREXHCFIDSHF5Qx5Eb1y-q91U13ejpyzgbL6Xzsk0RsWeIvMm5HA-yje067iYz70MxzY}=
      
    
    

# Hack-a-Sat2 Qualifier 2021:� Take Out the Trash

  
**Category** :� Deck 36, Main Engineering

**Points: � 142

**Solves: � 24

**Description:**

A cloud of space junk is in your constellation's orbit= al plane. Use the
space lasers on your satellites to vaporize it! Destroy at l= east 51 pieces
of space junk to get the flag.

The lasers have a range of 100 km and must be provided= range and attitude to
lock onto the space junk. Don't allow any space junk to approach closer than
10 km.

Command format:

    
    
    [Time_UTC] [S=
    at_ID] FIRE [Qx] [Qy] [Qz] [Qw] [Range_km]=
    
    
    
     

Command example:

    
    
    2021177.014500 SAT1 FIRE -0.7993071278793108 0.256914502808931=
    4 0.0 0.5432338847750264 47.85760531563315

`

This command fires the laser from Sat1 on June 26, 202= 1 (day 177 of the
year) at 01:45:00 UTC and expects the target to be approximately= 48 km away.
The direction would be a [0,0,1] vector in the J2000 frame rotated= by the
provided quaternion [-0.7993071278793108 0.2569145028089314 0.0
0.5432338847750264] in the form [Qx Qy Qz Qw].

One successful laser command is provided for you (note: there are many
possible combinations of time, attitude, range, and spacecra= ft to destroy
the same piece of space junk):

    
    
    2021177.002200 SAT1 FIRE -0.6254112512084177 -0.10281341941423=
    379 0.0 0.773492189779751 84.9530354564239

`

**Ticket:**

    
    
    ticket{mike202103bravo2:GE8s0nQV-5AuI3AlQRECYw5t0R6DqtrN5yS9I4=
    czUwfqTiTB6d7a625ki8wzxDnuWA}
    
    
     

**Connecting:**

    
    
    hard-coal.satellitesabove.me:5007
    
    
     

**Files:**

�        [http=
s://static.2021.hackasat.com/hxch0sjllud2ph3ff2dqg80dajn4](3D"https://static.2021.hackasat.com/hxch0sjllud2ph3ff2dqg80dajn4")

�        [http=
s://static.2021.hackasat.com/n47ad4ilw8r88gxpfm96bx0dyt2s](3D"https://static.2021.hackasat.com/n47ad4ilw8r88gxpfm96bx0dyt2s")

## Write-up

_By Kevin Farley, part of the SingleEventUpset team <= o:p>_

In-line with prior Hack-a-Sat problems, we ultimately = needed to do some
quaternion calculations. The prompt had provided trajectory data= for �space
junk� which we need to destroy, as well as satellites which do the destroying.
The solution needed to provide firing information which could d= estroy 51
pieces of space junk and prevent any from getting too close. Relevant
parameters include the UTC timestamp (indexing into the trajectory data) and
the quaternion displacement from the J2000 frame [0,0,1].

### Approach

Our general approach was to first detect when space ju= nk was in range of our
satellites. From that point we needed to calculate the quaternions, and then
format commands to clear out the debris. This was an iterative process; but
rather than providing snippets, the process will be = laid out here and the
final code will be documented in the �Code� subsection.

During the process we trialed a few different modules = to do our calculations
and interactions. In the end, the team used Python3 alongs= ide the skyfield
and numpy python packages.

Note that we have two code artifacts: one which genera= tes commands for the
satellites ( _generate_commands.py_ ) _,_ and the o= ther which feeds a list
of commands (via file) to the hack-a-sat problem ( _sen= d_commands.py_ ). The
final subsection documents the solution output resulting in the flag.

### Process

The first step was to import the provided TLE data int= o the skyfield python
package. From this point, we wrote code to detect when space junk was within
firing range. This is possible by indexing into the TLE data with a time
iteration loop. For each time increment we check the various satellite and
space junk positions per the skyfield API. A time increment of one minute was
selected as it generated commands in a reasonable amount of = time without
allowing any of the junk within 10km of any of the satellites.

After detecting some possible timestamps to fire at the junk, we took a stab
at calculating the quaternions and drafting some comma= nds. We quickly ran
into 2 issues.

1.&n;= bsp;     Satellites have a cool down period

2.&n;= bsp;     Our quaternion calculations were missing the= ir mark

The first point was solved by drafting some logic to t= rack satellite
availability. For any given time incre= ment, we created a list of available
satellites. If a command was generated for a= given satellite, it was removed
temporarily from the list of available satellites. Each satellite was returned
to its available state at the start of the next time increment.

The second point was a bit more convoluted. Our origin= al approach was to use
scipy�s spatial transform submodule. More specifically, the Rotation class and
a= lign_vectors method. Some code was developed to heighten our degree of
confidence, howev= er we still had issues.

To find the solution, we had to take a step back. It s= eemed prudent to try
to re-produce the quaternion provided in the prompt. As that command was
verified to work, we figured that if we could programmatically reproduce it,
then we could plug it in to the existing code for a valid solution. After
trying a variety of inputs and modules, we ultimately ended= up using some
math from earlier in the CTF�Deck 36�s first problem. We took the difference
of satellite 1 and the known space junk, then normalized the vec= tor and
plugged it into the quaternion calculation previously mentioned. This finally
provided the quaternion we were looking for and is notated in the q= uad
function of the solution code ( _generate_commands.py_ ).

Later analysis showed that even though the angle betwe= en our
�scipy.spatial.transform.Ro= tation� solution and the accepted solution was
exactly 0 degrees, the grading system was only accepting a quaternion which
used the minimum angular rotation bet= ween [0,0,1] and the target angle. The
problem was that the grading system was c= omparing the _quaternions_ rather
than the _pointing vector resulting from applying the quaternion_. The problem
was undercons= trained because it did not specify a second alignment vector.
Therefore, it has an = infinite number of valid quaternions that are correctly
pointing at the space junk b= ut with different values for the �roll� of the
satellite (aka which way is �up� while you are pointing at the space junk).
However, it was only accepting o= ne specific quaternion solution. We
eventually figured out the issue with the scoring and were able to work around
it by manually constructing the quater= nions after reverse-engineering the
algorithm used to compute the example quatern= ion.

### Code

#### generate_commands.py

    
    
    from math import dist
    
    
    from <=
    span
    class=3DGramE>scipy.spatial.transform import Rotation
    
    
    spacejunk.tle'
    
    
    sats.tle'
    
    
    sats =3D load.tle_file(SATS_FILE)=
    
    
    
    spacejunk =3D load.tle_file(SPACEJUNK_FILE)=
    
    
    
    ts =3D load.timescale()
    
    
    time_iter =3D 0
    
    
    detected_junk =3D {}
    
    
    available_sats =3D [sat.name for sat in <=
    span
    class=3DSpellE>sats]
    
    
     
    
    
    �� �[Sat_ID] FIRE [Qx]������������� [Qy]��������������� <=
    /span>[Qz] [Qw]�������������� [Range_km]
    
    
    ��� '''usage: fmt_cmd(t, sat, qx, qy, qz, qw, distance)'''
    
    
    ��� return f'{utc.utc_strftime("%Y%j.%H%M%S")} {sat.name.upper()} FIRE {qx} {qy} {qz} {qw} {range_km}'
    
    
    ��� v1 =3D [0,0,1]
    
    
    ��� v2 =3D vec
    
    
    ��� x, y, z =3D np.cross(v1, v2)
    
    
    ��� w =3D 1 + np.dot(v1, v2)
    
    
    ��� v3 =3D [x, y, z, w]
    
    
    ��� norm_len =3D np.sum([_i**2 for _i in v3])
    
    
    ��� norm_sf =3D 1 / np.sqrt(norm_len)
    
    
    ��� return [norm_sf * _i for _i in v3]
    
    
    ��� # Kill only as many as we nee=
    d to
    
    
    ��� while len(detected_junk.keys()) < TO_KILL:
    
    
    ������� current_time =3D ts.utc(2021, 6, 26, 0, time_iter=
    )
    
    
    ������� for junk in spacejunk:
    
    
    ����������� current_junk_pos =3D junk.at(cur=
    rent_time)
    
    
    ����������� for sat in sats:
    
    
     ���������������if sat.name in available_sats:
    
    
    ������������������� current_sat_pos =3D sat.at(curre=
    nt_time)
    
    
    ������������������� distance =3D =
    (current_sat_pos - current_junk_p=
    os).distance().km
    
    
    ������������������� if distance &=
    lt;=3D 10 and junk.name not in detected_junk.keys():=
    
    
    
    ����������������������� print(f'{=
    current_time.utc_datetime<=
    span
    class=3DGramE>()}� {junk.nam=
    e} is TOO CLOSE TO {sat.name} ({distance} km)')
    
    
    ������������������� elif distance <=3D 90:
    
    
    ����������������������� #print(f'=
    {current_time.utc_datetime()}� {=
    junk.name} is in range of {sat.name} ({distance} km)')
    
    
    ����������������������� if not detected_junk.get(junk.name) and sat.name in available_sats:
    
    
    ��������������������������� detected_junk[junk.name] =3D (sat.name, current_time.utc_datetime())
    
    
    ��������������������������� available_sats.remove(sat.=
    name)
    
    
    ��������������������������� junk_vec =3D np.array((current_junk_pos - current_sat_p=
    os).position.km)
    
    
    ��������������������������� junk_vec =3D junk_vec / <=
    span
    class=3DSpellE>np.linalg.norm(junk_vec)
    
    
    ��������������������������� fin =
    =3D quad(junk_vec)
    
    
    ��������������������������� f.write(fmt_cmd(current_time, sat, fin[0], fin[1], fin[2], fin[3], di=
    stance) + '\n')
    
    
    ����������������������� # print(<=
    span
    class=3DSpellE>len(detected_junk.keys()))
    
    
    ������� available_sats =3D [sat.name for sat in sats]
    
    
    ������� time_iter +=3D 1
    
    
     

#### send_commands.py

    
    
    from pwn import *
    
    
    -coal.satellitesabove.me'
    
    
    conn.recvuntil=
    (b'Tic=
    ket please:')
    
    
    conn.send(TICKET + b'\n')=
    
    
    
    conn.recvuntil=
    (b'Pro=
    vide command sequences:')
    
    
    rb') as =
    file:
    
    
    ��� for i in range (0,52):
    
    
    ������� print(f'Sending {i}')
    
    
    ������� print(conn.recvuntil(b':'))=
    
    
    
    ������� ln =3D file.readline()=
    
    
    
    ������� print(ln)
    
    
    ������� conn.send(ln)
    
    
    conn.interactive()=
    
    
    
     

### Solution

After running _generate_commands.py_ against the provided trajectory data, we
generated a _cmds.txt_ which got fed to <= i>send_commands.py_. This led to
the following result:

    
    
    All commands entered.
    
    
      
    
    
    
    
    # Hack-a-Sat2 Qualifier 2021:� groundead
    
    
    
    
      
    
    **Category** :� Presents from Mar=
    co
    
    
    
    
    **Points: � 80
    
    
    
    
    **Solves: � 52
    
    
    
    
    **Description:**
    
    
    
    
    you're groundead
    
    
    
    
    **Ticket:**
    
    
    
    
    
    ticket{kilo440990lima2:GMO6e_EYV3j2=
    3LQr2poHR_irrW4KpK-BjZ1rdGhinKKGYtUYRi46VXtZOOd-NGGGtQ}
    
    
     

**Connecting:**

    
    
    unfair-cookie.satellitesabove.me:5001=
    
    
    
     

**Files:**

�        [http=
s://static.2021.hackasat.com/mai9wvewp0avwos5ppxbg6lqdb6i](3D"https://static.2021.hackasat.com/mai9wvewp0avwos5ppxbg6lqdb6i")

## Write-up

_By Jonathan, part of the SingleEventUpset team = _

We used IDA Pro to disassemble and decompile the chall= enge binary.� We
identified that main() starts a producer thread (= getSatellitePacketBytes)
and a consumer thread (processSatellitePacketBytes):

![](3D"SingleEventUpsetQualsTechnicalPaper_files/image010.jpg")

getSatelliteP= acketBytes() processes incoming bytes and, among other things,
enforces that the incoming command ID always be set to 7.� Otherwise, it
rejects the input and prints "That sequence of hex characters did not work.
Try again." to stdout.

In processSat= ellitePacketBytes() we see that the max command ID is 8.�
Interestingly, compared to IDA Pro, Ghidra provided a more useful de=
compilation of the command handler logic:

![](3D"SingleEventUpsetQualsTechnicalPaper_files/image012.jpg")

We can see that the command nominally executed (7) corresponds to the
�Handling Test Telemetry� command, which matches the output that we regular=
ly see when fuzzing stdin.

To accelerate local testing/debugging, we patched the challenge binary to
remove sleeps/delays.

The goal must be to find a way to execute command ID <= span
style=3D'background:aqua;mso-highlight:aqua'>8 to coerce the flag to= be
dumped.

Immediately, we assume that we must abuse the queuing mechanism to inject a
single command, causing the parser to think that there are two commands
queued.� We notice= d that the magic hex value "1acffc1d" was being used in
getSatellitePack= etBytes() as a delimiter between successive commands:

![](3D"SingleEventUpsetQualsTechnicalPaper_files/image014.jpg")

...

![](3D"SingleEventUpsetQualsTechnicalPaper_files/image016.jpg")

This magic value is significant for its use in CCSDS a= nd ASM (see also
credence clearwater space data systems).

The same magic value was being used in processSatellitePacketBytes= ():

![](3D"SingleEventUpsetQualsTechnicalPaper_files/image018.jpg")

Some cursory reverse engineering reveals that the magi= c hex value "1acffc1d"
seems to be inserted between incoming commands by getSatellitePacketBytes()
and used by processSatellitePacketBytes() to de= limit successive commands.

Our attempts then center around abusing the queuing mechanism to inject a
single command, causing the consumer to think that th= ere are two commands
queued.� This requ= ires the use of the magic hex value "1acffc1d" as the
delimiter between successive commands.� The first command is built to pass all
necessary checks (command 7), then the delimiter "1acffc1d", then the command
that we want to execute (command 8).

This results in the following sequence:

`0f ff 56 01 071acffc1d<= /span>0f 01 01 01 08<= /o:p>`

Note, while the parsed bytes expect to be separated by spaces, the delimiter
itself does not have such limitations.

We used pwntools to script= the solution.� Here�s the solution scri= pt:

    
    
    #!/usr/bin/python3<=
    /span>
    
    
    2:GMO6e_EYV3j23LQr2poHR_irrW4KpK-BjZ1rdGhinKKGYtUYRi46=
    VXtZOOd-NGGGtQ}'
    
    
    -cookie.satellitesabove.me'=
    
    
    
    conn.recvuntil=
    (b'Tic=
    ket please:')
    
    
    conn.send(TICKET + b'\n')=
    
    
    
    conn.recvuntil=
    (b'>')=
    
    
    
    conn.send(b'0f ff 56 01 071acffc1d0f=
     01 01 01 08\n')
    
    
    conn.interactive()=
    
    
    
     

After running this script, there is a short delay before the flag is dumped.

`  
`

` `

# Hack-a-Sat2 Qualifier 2021:� Fiddlin' John Carson

  
**Category** :� Guardians of the�=

**Points: � 22

**Solves: � 232

**Description:**

Where do you come from?

**Ticket:**

    
    
    ticket{whiskey465080romeo2:GCw2dSO4=
    sBTqMsnCePG9DksVFzZTwjAt2f_6WzKFqfHOakXfx1xpazWSxHu3H8Iusg}
    
    
     

**Connecting:**

    
    
    derived-lamp.satellitesabove.me:5013<=
    /pre>
    
    
     

## Write-up

_By Irsyad, part of the SingleEventUpset team_

Upon connecting to the challenge server, we are prompt= ed with the scenario:

    
    
    Your spacecraft reports that its Cartesian ICRF position (km) =
    and velocity (km/s) are:
    
    
    �� [8449.40130=
    5, 9125.794363, -17.461357]
    
    
    ������ 2021-06-26-19:20:00.0=
    00-UTC
    
    
     

``#!/`usr/bin/python3<= /span>`

    
    
    isot', scale=3D'utc')
    
    
    cur_orbit =3D orbital.elements.KeplerianElements.from_state_vector(r, v=
    , orbital.bodies.earth, ref_epoch<=
    /span>=3Dt)
    
    
    print(�True anomaly: {}�.format(cur_orbit.f * (180/math.pi)))
    
    
    <=
    span
    style=3D'font-size:8.0pt;font-family:Consolas;color:#24292E;border:none win=
    dowtext 1.0pt;
    mso-border-alt:none windowtext 0in;padding:0in'> 

``KeplerianElements`:`<= /pre>

    
    
    ��� Semimajor axis (a)�� ������������������������=3D� 24732.886 km
    
    
    ��� Eccentricity (e)�� ��������������������������=3D����� 0.706807
    
    
    ��� Inclination (i)������������������=
    ����������� =3D����� 0.1 deg=
    
    
    
    ��� Right ascension of the ascend=
    ing node (raan) =3D���� 90.2 deg
    
    
    ��� Argument of perigee (arg_pe=
    )�� ��������������=3D��� 226.6 deg
    
    
    ��� Mean anomaly at reference epo=
    ch (M0)�������� =3D���� 16.5 deg
    
    
    ��� Period (T)�� ��������������������������������=3D 10:45:09=
    .999830
    
    
    ��� Reference epoch (ref_epoch)�� ���������������=3D 2021-06-26T19:20:00.000
    
    
    ������� Mean anomaly (M)������������������������ =3D���� 16.5 deg
    
    
    ������� Time (t)�� ������������������������������=3D 0:00:00
    
    
    ������� Epoch (epoch)�� �������������������������=3D 2021-06-26T=
    19:20:00.000
    
    
     

``What is its orbit (expressed as Keplerian elements a, e, i, Ω, ω, and υ)?

    
    
      
    
    
    
    
    _ _
    
    
    
    
    # Hack-a-Sat2 Qualifier 2021:� Cotton Eye GEO
    
    
    
    
      
    
    **Category** :� Guardians of the�=
    
    
    
    
    
    **Points: � 82
    
    
    
    
    **Solves: � 50
    
    
    
    
    **Description:**
    
    
    
    
    Where do you go?
    
    
    
    
    **Ticket:**
    
    
    
    
    
    ticket{charlie631677foxtrot2:GKm5yZ=
    pkXYc6ZtiLirUG0GNE4o0RV33HrYP3wj2Yu_UQwGKCDCd2paizAv00mmZa-A}
    
    
     

**Connecting:**

    
    
    visual-sun.satellitesabove.me:5014
    
    
     

## Write-up

_By Irsyad, part of the SingleEventUpset team_

Upon connecting to the challenge server, we are prompt= ed with the scenario:

    
    
    Your spacecraft from the first Kepler challenge is in a GEO tr=
    ansfer orbit.
    
    
    �� [8449.40130=
    5, 9125.794363, -17.461357]
    
    
    ������ 2021-06-26-19:20:00.0=
    00000-UTC
    
    
     

`We will be building off the script created in the previous prob= lem. To get
a better idea on where we are, we can use the �orbitalpy� library to plot our
current orbit:`

    
    
    from orbital import plot
    
    
     

![](3D"SingleEventUpsetQualsTechnicalPaper_files/image019.png")

Our apocenter seems to be at GEO, but our pericenter is still very close to
the Earth. To increase our pericenter altitude, we need= to perform a burn at
apocenter. To get the time to apocenter, we can propagate= our true anomaly to
pi radians, since true anomaly is the angle between pericen= ter and the
orbiting body.

    
    
    from orbital import plot
    
    
    cur_orbit.propagate_anomaly_to(f=3Dm=
    ath.pi)
    
    
     

This gives us a time of 2021-06-27T00:12:59.166 and a = plot of:

![](3D"SingleEventUpsetQualsTechnicalPaper_files/image020.png")

Finally, we need to find the delta-v required to incre= ase our pericenter to
GEO (35740 km from sea level). �Orbitalpy� provides maneu= ver functions for
common maneuvers. The following code constructs a maneuver th= at would
increase our pericenter to GEO:

    
    
    from orbital import plot, Maneuver
    
    
    cur_orbit.apply_maneuver(man1)
    
    
     

Once we had the new orbit, we could subtract the old o= rbit velocity from the
new orbit velocity to get the delta-v. However, the eccentricity of this
maneuver did not fit the constraints of the problem. T= he new orbit�s
eccentricity was 0.003177401688221862, and we needed an eccentricity of less
than 0.001. After some brute forcing, we found the altitude required to get
our eccentricity less than 0.001:

    
    
    from orbital import plot, Maneuver
    
    
    plot(cur_orbit, maneuver=3Dman1)
    
    
    cur_orbit.apply_maneuver(man1)
    
    
     

![](3D"SingleEventUpsetQualsTechnicalPaper_files/image021.png")

Our final script, including the brute-forcing, is:

    
    
    import orbital
    
    
    parser.add_argument("target")
    
    
    parser.add_argument("port")
    
    
    parser.add_argument("ticket")
    
    
    args =3D parser.parse_args()
    
    
    ��� value =3D altitude + test_val 
    
    
    ����print(f"[*] Testing alti=
    tude: {value}")
    
    
    ��� try:=
    
    
    
    ������� r =3D orbital.utilities.Position=
    (8449.401305 * 1000, 9125.794363 * 1000, -17.461357 * 1000)
    
    
    ������� v =3D orbital.utilities.Velocity=
    (-1.419072 * 1000, 6.780149 * 1000, 0.002865 * 1000)
    
    
    ������� t =3D astropy.time.Time("20=
    21-6-26T19:20:00", format=3D'isot', scale=3D'utc')
    
    
    ������� cur_orbit =3D orbital.elements.KeplerianElements.from_state_vector(r, v, =
    orbital.bodies.earth, ref_epoch<=
    /span>=3Dt)
    
    
    ������� #plot(cur_orbit)
    
    
    ������� cur_orbit.propagate_anomaly_to(f=3Dnumpy.pi)
    
    
    ������� old_v =3D cur_orbit.v
    
    
    ������� #plot(cur_orbit)
    
    
    ������� man1 =3D Maneuver.set_pericenter_altitude_to((value * 1000))
    
    
    ������� cur_orbit.apply_maneuver(m=
    an1)
    
    
    ������� #plot(cur_orbit)
    
    
    ������� new_v =3D cur_orbit.v
    
    
    ������� data =3D (new_v - old_v)/1000<=
    /o:p>
    
    
    ��� except Exception as e:
    
    
    ������� print(f"Got exception=
    : {e}")
    
    
    ������� continue
    
    
    ��� test =3D str(data.x)
    
    
    ��� if test =3D=3D "nan"=
    ;:
    
    
    ������� continue
    
    
    ��� print(data)=
    
    
    
    ��� with remote(args.target,args.port) as =
    conn:
    
    
    ������� conn.recvuntil(b'Ticket please:')
    
    
    ������� conn.sendline(args.ticket)
    
    
    ������ �conn.recvuntil(b'Time:')
    
    
    ������� conn.sendline(b"2021-=
    06-27-00:12:59.000000-UTC")
    
    
    ������� conn.recvuntil(b':')<=
    /o:p>
    
    
    ������� conn.sendline(str(data.x))
    
    
    ������� conn.recvuntil(b':')<=
    /o:p>
    
    
    ������� conn.sendline(str(data.y))
    
    
    ������� conn.recvuntil(b':')<=
    /o:p>
    
    
    ������� conn.sendline(str(data.z))
    
    
    ������� print("[.] Awaiting response...")=
    
    
    
    ������� print(conn.recvuntil(b'\n\n').de=
    code())
    
    
    ������� l =3D conn.recvline()=
    
    
    
    ������� print(l.decode())
    
    
    ������� if not l.startswith(b"That didn't work, try again!"):
    
    
    ����������� print(conn.recvline().decode())<=
    o:p>
    
    
    ����������� break
    
    
    Velocity(x=3D-0.9632461822327666, y=3D-1.0262562401=
    028483, z=3D0.0019905098232938082)
    
    
    flag{charlie631677foxtrot2:GCNwnESuR4pK8g6KjJlYrLD_rGKXFQj7biUirIuiUZDAKEn6-WQX=
    pdLTc8mKKTDPZHwkuCgxTcoBRk-XC9Q3zrQ}

