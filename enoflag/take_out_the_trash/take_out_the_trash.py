# requirements: pip3 install skyfield pyquaternion numpy
from skyfield.api import EarthSatellite, load
from pyquaternion import Quaternion

import numpy as np

ts = load.timescale()

def import_tles(filename):
    sats = []
    with open(filename) as f:
        while True:
            name = f.readline()
            if name == "":
                break
            l1 = f.readline()
            l2 = f.readline()
            sat = EarthSatellite(l1.strip(),l2.strip(),name.strip(), ts)
            # print(sat)
            sats.append(sat)

    return sats

sats = import_tles("sats.tle")
debris = import_tles("spacejunk.tle")

vaporized = [None for _ in debris]
last_lazor_shot  = [0 for _ in debris]

def propagate(t):
    sats_t = [sat.at(t) for sat in sats ]
    debris_t = [deb.at(t) for deb in debris ]
    return sats_t, debris_t

def find_intersections(t, thresh):
    sats_t, debris_t = propagate(t)

    for s_i, s in enumerate(sats_t):
        dist_list = []
        idx_list = []
        for d_i, d in enumerate(debris_t):
            if vaporized[d_i] is not None:
                continue
            dist_list.append(np.linalg.norm(s.position.km - d.position.km))
            idx_list.append(d_i)

        d_i = idx_list[np.argmin(dist_list)]
        test_encounter(t, s, s_i, debris_t[d_i], d_i, thresh)
                
def test_encounter(t, s, s_i, d, d_i, thresh):

    if np.linalg.norm(s.position.km - d.position.km) < thresh:
        if time.utc_datetime().timestamp() - last_lazor_shot[s_i] < 60:
            return
        
        vaporized[d_i] = (t, s_i, d_i)
        last_lazor_shot[s_i] = t.utc_datetime().timestamp()

        target_vector = d.position.km - s.position.km
        dist_km = np.linalg.norm(target_vector)

        v1 = np.array([0,0,1])
        target_dir = target_vector / dist_km

        # v1, target_dir = target_dir, v1
        R = np.cross(v1, target_dir)
        q1 = R[0]
        q2 = R[1]
        q3 = R[2]
        q4 = np.dot(v1, target_dir) + np.sqrt(np.linalg.norm(v1) ** 2 * np.linalg.norm(target_dir) ** 2)

        q = Quaternion(q1, q2, q3, q4).normalised

        day_frac = 177 - 26 \
            + time.utc.day \
            + 1000 * time.utc.year \
            + time.utc.hour / 100 \
            + time.utc.minute / 10000 \
            + time.utc.second / 1000000

        print(f"{day_frac:.6f} SAT{s_i + 1} FIRE {q[0]} {q[1]} {q[2]} {q[3]} {dist_km}")

        if np.linalg.norm(s.position.km - d.position.km) < 30:
            print("DANGER:", t.utc, sats[s_i].name, debris[d_i].name)


# for thresh in [50, 60, 80, 95]:
for day in range(5):
    for hour in range(24):
        for m in range(0, 60):
            for s in [0, 30]:
                time = ts.utc(2021, 6, 26+day, hour, m, s)
                find_intersections(time, 100)

# time = ts.utc(2021, 6, 26, 0, 22, 0)
# sats_t, debris_t = propagate(time)
# test_encounter(time, sats_t[0], 0, debris_t[0], 0)

# print(sats)
# print(debris)