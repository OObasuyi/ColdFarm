import acitoolkit.acitoolkit as aci_mod
from tetpyclient import RestClient
import pandas as pd
from time import sleep
from utils import Rutils, log_collector
from json import loads, dumps
from socket import gethostbyaddr, herror
import requests


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
            aci_endpoints, site_name = self._aci_engine(site_data=pl,apic_info=apic_info)
            if site_name:
                site_coll.append(site_name)
                aci_dfs.append(aci_endpoints)

        # if a site was unreachable in the prim list then we need to search the sec list
        for sl in sec_list:
            if sl not in site_coll:
                aci_endpoints, site_name = self._aci_engine(site_data=sl, apic_info=apic_info)
                if site_name:
                    site_coll.append(site_name)
                    aci_dfs.append(aci_endpoints)

        # combine and normalize
        aci_dfs = pd.concat(aci_dfs, axis=0).drop_duplicates(subset=['iface_mac'])
        aci_dfs['dns_name'] = aci_dfs['iface_mac'].apply(lambda x: self._dns_socket_handle(x))
        return aci_dfs

    def csw_handler(self):
        csw_info = self.config['CSW']
        inventory_query = {
            "dimensions": ["host_name", "iface_mac", "ip", "os"],
            "filter": {"type": "and", "filters": [{"type": "subnet", "field": "ip", "value": csw_info['CSW_filter_IP']}]}
        }

        csw_client = RestClient(csw_info['secure_workload'], verify=False, api_key=csw_info['api_key'], api_secret=csw_info['api_secret'])

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
    
    def send_data_to_ise(self):
        # pull info from csw and aci
        aci_data = self.aci_handler()
        csw_data = self.csw_handler()
        ise_info = self.config['ISE']

        # first need to check if the macs are in ISE already if they are then need to apply update to them
        requests.get(url=ise_info['node'])


    def _aci_engine(self,site_data,apic_info):
        for url_data, site_name in site_data.items():
            aci_endpoints = self._aci_spooler(url=url_data, login=apic_info['username'], password=apic_info['password'])
            # if APIC didnt timeout mark it and get the res
            if aci_endpoints:
                return aci_endpoints, site_name
            else:
                self.logger.error(f'ACI: could not reach {site_name} @ {url_data}')
                return None, None

    def _dns_socket_handle(self,x):
        try:
             return gethostbyaddr(x)
        except herror as error:
            self.logger.debug(f'DNS issue for {x}: error code: {error}')
            return None

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
