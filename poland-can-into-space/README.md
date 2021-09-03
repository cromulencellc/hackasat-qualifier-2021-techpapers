# Hack-A-Sat 2 Quals write-ups
by Poland Can Into Space

## Problems are Mounting

First, by rotating the satellite by 180 degrees in three axes, we've found which sensor is broken.
Then, using a perturb-and-observe algorithm (randomly varying position and checking voltages
on solar panels), we have found angles for the maximum solar irradiation - for both one correct
sensor and one broken. Then, by calculating the inverse of rotation matrix for known good
sensor, we've calculated the satellite attitude, and then by multiplying it with the angle of the
maximum voltage of broken sensor, we've calculated its mounting vector.

## IQ

We are given the bits and QPSK mapping. By observing that the first bit maps to the I axis and
the second bit maps to the Q axis and knowing that output follows the same convention, we can
directly change for bits to IQ values. For '0' bit, we print '-1.0', and for '1' bit, we print '1.0'.

## Mr. Radar

We are given the radar measurements of the satellite from the Earth (azimuth, elevation, range).
By knowing that the orbit can be defined by 3-axis position (XYZ) and 3-axis velocity at a given
time, we try to find the values from the provided measurements. First, we have to change the
frame of reference from Earth's local to GCRF frame and make all calculations in XYZ in GCRF.
We can calculate the initial approximation of the solution by taking the first two points (we have
the position and velocity). To improve the accuracy, we use the perturb-and-observe algorithm,
randomly varying parameters to find a better solution that fits all measurement points. After
many iterations, we have a good enough orbit approximation which is the solution.

## Linky

In this task, we used AMSAT link budget spreadsheet to do all the calculations. In each stage,
we’ve filled the spreadsheet with given data and responded with the required information.
Antenna gain and G/T in the antenna sheet, and the rest of the spreadsheet was filled with
provided data to calculate full link budget, which given the transmit power.

## Saving spinny

First, we predicted all satellite passes in 12h span from 2021-06-26 00:00:00 UTC for every
ground station. Then, by trial-end-error, we tried sending a command one at a time at each
pass, trying to find a communication window (if the satellite was not pointing its antenna at a
ground station, the checker responded with "no link" information). Finally, after a couple of tries,
we found the correct time slot for each of the three commands and manually submitted a
solution.

## Error Correction

We are given a QPSK-modulated IQ file. Using gnuradio and inspectrum, we found that it uses
4-samples per symbol and decoded the waveform into IQ bits. We guessed that this is
CCSDS-compliant telemetry link, with typical convolutional code R=1/2, K=7 (and we've thought
that maybe it does use a concatenated code with Reed-Solomon, but not). By trial-and-error, we
found correct QPSK mapping to convolutional code bits and decoded the message finding
proper viterbi decoder settings. The flag was in the plaintext in the decoded message.

## Cotton eye GEO

We start off with some reference manoeuvre (can be the circularization burn from Hohmann
transfer between given orbits, or even just dv and dt set to 0). Then we run simulated annealing
optimization loops, which modify the velocities and burn time slightly by adding or removing a
random value to each component. Then we apply this manoeuvre to our orbit and calculate the
deviations on semi-major-axis, eccentricity and inclination. If we managed to get a better orbit
(lower deviations sum), we save this as a new reference, if not we reject it. We run this for many
iterations until orbital elements deviations are within tolerance range.

## Hindsight

We implement star tracking based on geometric shapes, in our case lines. We compute the
distance between each pair of stars in the catalogue. Then we compute distance between each
pair of stars in the star tracker field of view. Then for each star from star tracker we search for a
star in the catalogue which has closest matching distances: first we pick the 2 distances with
smallest absolute difference, and then we sum those differences to get the "error", and finally
we choose the one for which the error was smallest.