import acitoolkit.acitoolkit as aci_mod
from tetpyclient import RestClient
import pandas as pd
from time import sleep
from json import loads, dumps
from socket import gethostbyaddr
from requests import Session
from utils import log_collector, Rutils


class Farm:
    UTILS = Rutils()

    def __init__(self, config: str = "config.yaml", verify_ssl=False):
        self.logger = log_collector(file_name='wastewater.log', func_name='ColdFarm')
        # move config file to new folder
        config = self.UTILS.create_file_path('configs', config)
        self.config = self.UTILS.get_yaml_config(config, self)
        self.ssl_verify = verify_ssl

    def pull_aci_data(self):
        site_coll = []
        aci_dfs = []
        apic_info = self.config['APIC']
        pri_list = apic_info['pri_dc']
        sec_list = apic_info.get('sec_dc')

        # since we have a list of DCs lets spool
        for pl in pri_list:
            aci_endpoints, site_name = self._aci_engine(site_data=pl, apic_info=apic_info)
            if site_name:
                site_coll.append(site_name)
                aci_dfs.append(aci_endpoints)

        # if a site was unreachable in the prim list then we need to search the sec list
        if sec_list:
            for sl in sec_list:
                if sl not in site_coll:
                    aci_endpoints, site_name = self._aci_engine(site_data=sl, apic_info=apic_info)
                    if site_name:
                        site_coll.append(site_name)
                        aci_dfs.append(aci_endpoints)

        # combine and normalize
        aci_dfs = pd.concat(aci_dfs, axis=0).drop_duplicates(subset=['iface_mac'])
        aci_dfs['dns_name'] = aci_dfs['ip'].apply(lambda x: self._dns_socket_handle(x))
        aci_dfs['iface_mac'] = aci_dfs['iface_mac'].apply(lambda x: x.lower())
        aci_dfs['dns_name'] = aci_dfs['dns_name'].apply(lambda x: x.lower())
        return aci_dfs

    def pull_csw_data(self):
        csw_info = self.config['CSW']
        inventory_query = {
            "dimensions": ["host_name", "iface_mac", "ip", "os"],
            "filter": {"type": "and", "filters": [{"type": "subnet", "field": "ip", "value": csw_info['CSW_filter_IP']}]}
        }

        csw_client = RestClient(csw_info['secure_workload'], verify=self.ssl_verify, api_key=csw_info['api_key'], api_secret=csw_info['api_secret'])

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
        csw_endpoints['host_name'] = csw_endpoints['host_name'].apply(lambda x: x.lower())
        return csw_endpoints

    def pull_ise_data(self, ise_session):
        ise_info = self.config['ISE']
        get_eps = f'{ise_info["node"]}/ers/config/endpoint'
        page_counter = 1
        page_list = []
        while True:
            # since ISE Pagenets the results
            eps_url = get_eps + f'?size=10&page={page_counter}'
            req = ise_session.get(eps_url)
            if req.status_code != 200:
                self.logger.critical(f'ISE: could not reach node at {get_eps}')
                self.logger.critical(f'ISE: code recvd from node {req.status_code} \n\n CONTENT:\n\n\ {req.content}\n\n')
                self.logger.critical(f'ISE: QUITTING PROGRAM!!!!!!')
                quit()
            else:
                # make one list
                for req_i in loads(req.content)['SearchResult']['resources']:
                    page_list.append(req_i)
                # if we have no more then break
                if '"rel" : "next"' in req.text:
                    page_counter += 1
                    # sleep(.5)
                    # else:
                    break
        ise_data = pd.DataFrame(page_list)

        return ise_data

    def send_data_to_ise(self, test_data=False, **kwargs):
        self.logger.info('Starting CSW/ACI ingestion to ISE')
        ise_info = self.config['ISE']
        bulk_create = f'{ise_info["node"]}/api/v1/endpoint/bulk'
        ise_session = Session()
        ise_session.verify = self.ssl_verify
        ise_session.headers = {"Accept": "application/json", "Content-Type": "application/json"}
        ise_session.auth = (ise_info['username'], ise_info['password'])

        # pull info from csw and aci and endpoint from ise
        if not test_data:
            aci_data = self.pull_aci_data()
            csw_data = self.pull_csw_data()
            # combine csw and aci
            combined_data = self._combine_aci_cws_df(aci_data, csw_data)

        # Testing only
        if test_data:
            from Test.tempcheck import input_generator
            combined_data = input_generator(amount=test_data,seed=kwargs.get('test_seed'))

        # create Templates based on new endpoints
        new_endpoints = self._ise_endpoint_template(combined_data)
        self.logger.info(f'ISE: attempting to create {len(combined_data)} endpoint in ISE')

        # this is gonna be two operations since its the most effienct way to make sure the endpoints are in with the v1 API and I cant get status updates on calls??
        create_meth = ise_session.post(bulk_create, data=new_endpoints)
        self.logger.info(f'ISE: received status code {create_meth.status_code} for trying to create {len(combined_data)} endpoints in ISE')
        if create_meth.status_code == 200:
            self.logger.debug(f'ISE: received back ID: {loads(create_meth.content)["id"]} from ISE')
        sleep(5)

        update_meth = ise_session.put(bulk_create, data=new_endpoints)
        self.logger.info(f'ISE: received status code {update_meth.status_code} for trying to update {len(combined_data)} endpoints in ISE')
        if update_meth.status_code == 200:
            self.logger.debug(f'ISE: received back ID: {loads(update_meth.content)["id"]} from ISE')
        pass

    def _aci_engine(self, site_data, apic_info):
        for url_data, site_name in site_data.items():
            aci_endpoints = self._aci_spooler(url=url_data, login=apic_info['username'], password=apic_info['password'])
            # if APIC didnt timeout mark it and get the res
            if isinstance(aci_endpoints, pd.DataFrame):
                return aci_endpoints, site_name
            else:
                self.logger.error(f'ACI: could not reach {site_name} @ {url_data}')
                return None, None

    @staticmethod
    def _combine_aci_cws_df(aci_df, csw_df):
        combined_df = aci_dfs = pd.concat([aci_df, csw_df], axis=0).drop_duplicates(subset=['iface_mac']).fillna('none')
        return combined_df

    def _aci_spooler(self, url, login, password):
        session = aci_mod.Session(url=url, uid=login, pwd=password, subscription_enabled=False, verify_ssl=self.ssl_verify)

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

    @staticmethod
    def _ise_endpoint_template(endpoints_dat: pd.DataFrame):
        endpoints_dat.rename(columns={'iface_mac': 'mac', "os": "assetDeviceType", "ip": "ipAddress"}, inplace=True)
        endpoints_dat['customAttributes'] = endpoints_dat.apply(lambda row: {
                                                                                'DataCenter HostName': row['host_name'] if row['host_name'] != 'none' else row['dns_name'],
                                                                                'DataCenter EPG': row['EPG'],
                                                                            }
                                                                , axis=1)
        endpoints_dat['name'] = endpoints_dat['host_name'].str.lower()
        endpoints_dat.drop(['host_name', 'EPG'], axis=1, inplace=True)
        endpoints_dat_json = endpoints_dat.to_json(orient='records', force_ascii=False)
        return endpoints_dat_json

    def _dns_socket_handle(self, x):
        try:
            return gethostbyaddr(x)[0].split(".")[0]
        except Exception as error:
            self.logger.debug(f'DNS issue for {x}: error code: {error}')
            return "none"


if __name__ == "__main__":
    coldF = Farm('config_test.yaml')

    # coldF.pull_csw_data()
    coldF.send_data_to_ise(test_data=True)
    # coldF.pull_ise_data()
