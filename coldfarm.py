import acitoolkit.acitoolkit as aci_mod
from tetpyclient import RestClient
import pandas as pd
from time import sleep
from json import loads, dumps
from socket import gethostbyaddr
from requests import Session
from ColdClarity.utilities import log_collector
from ColdClarity.ise_control import Clarity
import re
import xml.etree.ElementTree as et


class Farmer(Clarity):

    def __init__(self, config: str = "config.yaml", verify_ssl=False):
        # super().__init__(config)
        self.logger = log_collector(file_name='wastewater.log',func_name='ColdFarm')
        # move config file to new folder
        config = self.UTILS.create_file_path('configs', config)
        self.config = self.UTILS.get_yaml_config(config, self)
        self.ssl_verify = verify_ssl

    def ise_web_login_action(self):
        ise_info = self.config['ISE']
        # ISE username and password
        if ise_info['authentication']['text_based']['use']:
            self.login_type = 'text'
            ise_username = ise_info['authentication']['text_based']['username']
            ise_password = ise_info['authentication']['text_based']['password']
            # encode cred str to pass as a post msg to ISE
            self.user = self.UTILS.encode_data(ise_username, base64=False)
            self.password = self.UTILS.encode_data(ise_password, base64=False)
            self.auth_source = ise_info['authentication']['text_based']['auth_source']
        # cert based
        elif ise_info['authentication']['cert_based']['use']:
            self.login_type = 'cert'
            cert_location = ise_info['authentication']['cert_based']['cert_pfx_location']
            # move cert to new folder
            self.cert_location = self.UTILS.create_file_path('certificate_information', cert_location)
            self.cert_passwd = ise_info['authentication']['cert_based']['cert_password']
        ise_session = Session()
        ise_session.verify = self.ssl_verify
        self.get_session(ise_session)
        return ise_session

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
        #if sec_list:
        #    for sl in sec_list:
        #       if sl not in site_coll:
        #            aci_endpoints, site_name = self._aci_engine(site_data=sl, apic_info=apic_info)
        #            if site_name:
        #                site_coll.append(site_name)
        #                aci_dfs.append(aci_endpoints)

        # combine and normalize
        aci_dfs = pd.concat(aci_dfs, axis=0).drop_duplicates(subset=['iface_mac'])
        aci_dfs['dns_name'] = aci_dfs['ip'].apply(lambda x: self._dns_socket_handle(x))
        aci_dfs['iface_mac'] = aci_dfs['iface_mac'].apply(lambda x: x.lower())
        aci_dfs['host_name'] = aci_dfs['host_name'].apply(lambda x: x.lower())
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

    def pull_ise_data(self,ise_session):
        ise_info = self.config['ISE']
        get_eps = f'{ise_info["node"]}/ers/config/endpoint'
        page_counter = 1
        page_list = []
        while True:
            # since ISE Pagenets the results
            eps_url = get_eps + f'?size=100&page={page_counter}'
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
                    sleep(.5)
                else:
                    break
        ise_data = pd.DataFrame(page_list)

        return ise_data


    def send_data_to_ise(self):
        ise_info = self.config['ISE']
        bulk_create = f'{ise_info["node"]}/ers/config/endpoint/bulk'
        ise_session = Session()
        ise_session.verify = False
        ise_session.headers = {"Accept": "application/json","Content-Type": "application/xml"}
        ise_session.auth = (ise_info['username'], ise_info['password'])

        # pull info from csw and aci and endpoint from ise
        aci_data = self.pull_aci_data()
        csw_data = self.pull_csw_data()
        #ise_data = self.pull_ise_data(ise_session)

        ######### TEST!!!!!!!!!####
        #from TEST.tempcheck import input_generator
        #combined_data = input_generator(seed=399)
        ######### TEST!!!!!!!!!####

        # check to see if data from DC is already in ISE if so remove them for and mark for updating
        # combine csw and aci
        combined_data = self._combine_aci_cws_df(aci_data,csw_data)
        # todo: need to make endpoint update flow
        combined_data['datastore_location'] = None
        for i in combined_data.index:
            com_data = combined_data.iloc[i]
            if com_data['iface_mac'].upper() in ise_data['name'].tolist():
                combined_data['datastore_location'].iloc[i] = ise_data['id'][ise_data['name'] == com_data['iface_mac'].upper()].iloc[0]
        combined_new_endpoints = combined_data[combined_data['datastore_location'].isnull()]

        # create templates based on new endpoints
        root, resources_list = self.ise_root_template()
        new_endpoints = self._ise_endpoint_template(root, resources_list,combined_new_endpoints)
        self.logger.info(f'ISE: attempting to create {len(new_endpoints)} endpoint in ISE')
        ret = ise_session.put(bulk_create, data=new_endpoints)

        if ret.status_code != 202:
            self.logger.critical(f'ISE: could not create bulk endpoint received code {ret.status_code}')
        else:
            # get location of bulk to see the status of op
            status_location = dict(ret.headers)['Location']
            while True:
                status_ret = ise_session.get(status_location)
                if status_ret.status_code == 200:
                    stat_info = loads(status_ret.content)['BulkStatus']
                    if stat_info['executionStatus'] == 'IN_PROGRESS':
                        self.logger.info(f'ISE: awaiting endpoint progress report on job {stat_info["bulkId"]}')
                        sleep(3)
                    elif stat_info['executionStatus'] == 'COMPLETED':
                        if stat_info['successCount'] == stat_info['resourcesCount']:
                            self.logger.info(f"ISE: endpoint bulk job {stat_info['bulkId']} successfully created")
                            self.logger.info(f"ISE: endpoint bulk job  COMPLETED  {stat_info['successCount']} OF {stat_info['resourcesCount']}")

                        else:
                            self.logger.critical(f"ISE: endpoint bulk job {stat_info['bulkId']} FAILED  {stat_info['failCount']} OF {stat_info['resourcesCount']}")
                        break
                else:
                    self.logger.critical(f'ISE: RECEIVED STATUS CODE {status_ret.status_code} when trying to create bulk endpoint {status_location}')
                    quit()

        pass

    @staticmethod
    def ise_root_template():
        root = et.Element('ns4:endpointBulkRequest', attrib={
            'operationType': 'create',
            'resourceMediaType': 'vnd.com.cisco.ise.identity.endpoint.1.0+xml',
            'xmlns:ns4': 'identity.ers.ise.cisco.com'
        })
        resources_list = et.SubElement(root, 'ns4:resourcesList')
        return root, resources_list

    def _aci_engine(self, site_data, apic_info):
        for url_data, site_name in site_data.items():
            aci_endpoints = self._aci_spooler(url=url_data, login=apic_info['username'], password=apic_info['password'])
            # if APIC didnt timeout mark it and get the res
            if isinstance(aci_endpoints,pd.DataFrame):
                return aci_endpoints, site_name
            else:
                self.logger.error(f'ACI: could not reach {site_name} @ {url_data}')
                return None, None

    def _combine_aci_cws_df(aci_df,csw_df):
        combined_df = aci_dfs = pd.concat([aci_df,csw_df], axis=0).drop_duplicates(subset=['iface_mac']).fillna('none')
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
    def _ise_template_creator(record_data: dict, update_record: str = False):
        """
        :type update_record: if this is set to False the template will return without the ID field. if you want to update a field fill this var with the appropriate ID
        MEANT FOR BULK OPs but can handle singles with bulk election
        """
        temp = {
            "ERSEndPoint": {
                "name": record_data["hostname"],
                "mac": record_data['mac'],
                "staticProfileAssignment": 'false',
                "staticProfileAssignmentDefined": 'false',
                "staticGroupAssignment": 'false',
                "staticGroupAssignmentDefined": 'false',
                "customAttributes": {
                    "customAttributes": {
                        "DataCenter_OS": record_data["os"],
                        "DataCenter_IP": record_data["ip"],
                        "DataCenter_Enforcement": "None"  # once we get this attr it will be filled
                    }
                }
            }
        }

        if update_record:
            temp['ERSEndPoint']['id'] = update_record
        return temp

    @staticmethod
    def _ise_endpoint_template(root,resources_list,endpoints:pd.DataFrame):
        for i in endpoints.index:
            endpoint = endpoints.iloc[i]
            endpoint['hostname'] = endpoint['hostname'] if endpoint['host_name'] != 'none' else endpoint['dns_name']
            
            endpoint_elm = et.SubElement(resources_list, 'ns4:endpoint', attrib={'description': endpoint['hostname']})
            custom_attributes = et.SubElement(endpoint_elm, 'customAttributes')
            nested_custom_attributes = et.SubElement(custom_attributes, 'customAttributes')
            for key, value in {'DataCenter_OS': endpoint['os'], 'DataCenter_HostName': endpoint['host_name'], 'DataCenter_IP': endpoint['ip'], 'DataCenter_Enforcement': 'None','DataCenter_EPG': endpoint['EPG']}.items():
                entry = et.SubElement(nested_custom_attributes, 'entry')
                entry_key = et.SubElement(entry, 'key')
                entry_key.text = key
                entry_value = et.SubElement(entry, 'value')
                entry_value.text = value

            mac_element = et.SubElement(endpoint_elm, 'mac')
            mac_element.text = endpoint['iface_mac']

            static_group_assignment = et.SubElement(endpoint_elm, 'staticGroupAssignment')
            static_group_assignment.text = 'false'

            static_profile_assignment = et.SubElement(endpoint_elm, 'staticProfileAssignment')
            static_profile_assignment.text = 'false'

        xml_str = et.tostring(root, encoding='UTF-8', xml_declaration=True)
        return xml_str

    def _dns_socket_handle(self, x):
        try:
            return gethostbyaddr(x)[0].split(".")[0]
        except Exception as error:
            self.logger.debug(f'DNS issue for {x}: error code: {error}')
            return None


if __name__ == "__main__":
    coldF = Farmer('config_test.yaml')
    coldF.logger.info('Starting ColdFarmer')
    # coldF.pull_csw_data()
    coldF.send_data_to_ise()
    # coldF.pull_ise_data()
