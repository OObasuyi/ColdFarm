import acitoolkit.acitoolkit as aci_mod
from tetpyclient import RestClient
import pandas as pd
from time import sleep
from utils import Rutils, log_collector
from json import loads, dumps


class Farmer:
    UTILS = Rutils()

    def __init__(self, config: str = "config.yaml"):
        self.logger = log_collector()
        # move config file to new folder
        config = self.UTILS.create_file_path('configs', config)
        self.config = self.UTILS.get_yaml_config(config, self)

    def aci_handler(self):
        site_coll = []
        aci_dfs = []
        apic_info = self.config['APIC']
        pri_list = apic_info['pri_dc']
        sec_list = apic_info['sec_dc']

        # since we have a list of DCs lets spool
        for pl in pri_list:
            for url_data, site_name in pl.items():
                aci_endpoints = self._aci_spooler(url=url_data, login=apic_info['username'], password=apic_info['password'])
                # if APIC didnt timeout mark it and get the res
                if aci_endpoints:
                    site_coll.append(site_name)
                    aci_dfs.append(aci_endpoints)

        # if a site was unreachable in the prim list then we need to search the sec list
        for sl in sec_list:
            if sl not in site_coll:
                for url_data, site_name in sl.items():
                    aci_endpoints = self._aci_spooler(url=url_data, login=apic_info['username'], password=apic_info['password'])
                    # if APIC didnt timeout mark it and get the res
                    if aci_endpoints:
                        site_coll.append(site_name)
                        aci_dfs.append(aci_endpoints)

    # TODO: what to do with dfs and site coll

    def csw_handler(self):
        csw_info = self.config['CSW']
        inventory_query = {
            "dimensions": ["host_name", "iface_mac", "ip", "os"],
            "filter": {"type": "and", "filters": [{"type": "subnet", "field": "ip", "value": csw_info['CSW_filter_IP']}]}
        }

        csw_client = RestClient(csw_info['API_ENDPOINT'], verify=False, api_key=csw_info['API Key'], api_secret=csw_info['API Secret'])

        # get inventory data
        raw_csw = csw_client.post('/inventory/search', json_body=dumps(inventory_query))

        # just in case its a dickhead
        if raw_csw.status_code == 200:
            csw_data = loads(raw_csw.content)
        else:
            self.logger.critical("YAY A NEW ERROR TO FIX")
            # TODO: more testing needed
            quit()

        # transform and normalize
        csw_endpoints = pd.DataFrame(csw_data["results"])
        csw_endpoints.drop_duplicates(subset='host_name', inplace=True)
        csw_endpoints.dropna(subset='host_name', inplace=True)
        return csw_endpoints

    def _aci_spooler(self, url, login, password):
        session = aci_mod.Session(url=url, uid=login, pwd=password, subscription_enabled=False)

        # error handle dont know the lib cause but not patching it now
        counter = 0
        while True:
            try:
                resp = session.login()
                if resp.ok:
                    break
                else:
                    self.logger.critical('Could not login to APIC')
            except Exception as error:
                self.logger.critical(f"ACI_SPOOLER: {error}")
                counter += 1
                sleep(.5)
            # we will try to see this APIC works for n times after that time out
            if counter > 5:
                self.logger.critical(f"SKIPPING {url} AS WE CANNOT REACH IT")
                return None

        # get mac and IP address from aci_mod and create a list
        ep_list = []
        endpoints = aci_mod.IPEndpoint.get(session)
        for ep in endpoints:
            epg = ep.get_parent()
            ep_list.append((ep.mac, ep.ip, epg.name))

        # transform and normalize
        aci_endpoints = pd.DataFrame(ep_list)
        aci_endpoints.rename(columns={0: 'iface_mac', 1: "ip", 2: "EPG"}, inplace=True)
        return aci_endpoints


if __name__ == "__main__":
    coldF = Farmer('config_test.yaml')
    coldF.logger.info('Starting ColdFarmer')
    coldF.csw_handler()