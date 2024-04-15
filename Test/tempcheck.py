import pandas as pd
import random
import string
from uuid import uuid4


def input_generator(amount: int = 25, prefix: str = 'labnet-', need_id: bool = False,seed:int=None):
    if seed and isinstance(seed,int):
        random.seed(seed)
    operating_systems = ['WindowsServer2012', 'Ubuntu', 'SuperSaverServer']
    real_oui= ['E0:CB:1D','40:92:1A','4C:EC:0F','98:40:BB']
    epg_choice = ['web-apps','databases','infra-core']
    data = []
    for _ in range(amount):
        mac_address = random.choice(real_oui).lower() +':' + ':'.join(['{:02x}'.format(random.randint(0, 255)) for _ in range(3)])
        ip_address = '.'.join([str(random.randint(0, 255)) for _ in range(4)])
        os = random.choice(operating_systems)
        epg = random.choice(epg_choice)
        hostname = prefix + ''.join(random.choices(string.ascii_lowercase + string.digits, k=5))
        rec_hold = {'host_name': hostname, 'iface_mac': mac_address, 'ip': ip_address, 'os': os, 'EPG': epg}
        if need_id:
            rec_hold['id'] = str(uuid4())
        data.append(rec_hold)

    return pd.DataFrame(data)


if __name__ == "__main__":
    df = input_generator()
    print(df)
