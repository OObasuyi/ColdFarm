import base64
import json

import pandas as pd
import requests
from tqdm import tqdm

from .utilities import Rutils, log_collector
from .requests_pkcs12 import Pkcs12Adapter
from os import getpid

requests.packages.urllib3.disable_warnings()


class Clarity:
    HEADER_DATA = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:106.0) Gecko/20100101 Firefox/106.0',
    }
    UTILS = Rutils()

    def __init__(self, config: str = "config.yaml",log_name: str = "clarity.log"):
        self.logger = log_collector(log_name)
        # move config file to new folder
        config = self.UTILS.create_file_path('config_information', config)
        self.config = self.UTILS.get_yaml_config(config, self)
        # not ideal but meh
        self.logger = log_collector(self.config.get('debug_console_login'))

        # Clarity username and password
        if self.config['authentication']['text_based']['use']:
            self.login_type = 'text'
            if self.config['authentication']['pipeline']:
                ise_username = self.config['authentication']['text_based']['username']
                ise_password = self.config['authentication']['text_based']['password']
            else:
                ise_username = input("username: ")
                ise_password = input("password: ")

            # encode cred str to pass as a post msg to Clarity
            self.user = self.UTILS.encode_data(ise_username, base64=False)
            self.password = self.UTILS.encode_data(ise_password, base64=False)
            self.auth_source = self.config['authentication']['text_based']['auth_source']
        # cert based
        elif self.config['authentication']['cert_based']['use']:
            self.login_type = 'cert'
            cert_location = self.config['authentication']['cert_based']['cert_pfx_location']
            # move cert to new folder
            self.cert_location = self.UTILS.create_file_path('certificate_information', cert_location)
            self.cert_passwd = self.config['authentication']['cert_based']['cert_password']

        # auth information
        self.ip = self.config['ise']['ip']
        # session information
        self.get_session()
        self.init_ise_session()
        self.phase = self.config['ComplytoConnect']['phase']

    def get_session(self,ise_session=None):
        self.logger.debug('Obtaining Session Object')
        if ise_session is None:
            self.session = requests.Session()
            self.session.verify = False
        else:
            self.session = ise_session

    def init_ise_session(self):
        url_csrf = f"https://{self.ip}/admin/JavaScriptServlet"
        # obtain CSRF token
        token_info = None
        csrf_header = self.HEADER_DATA.copy()
        csrf_header['FETCH-CSRF-TOKEN'] = '1'
        # Needed FOR USER/PASS AUTH
        if self.login_type == 'text':
            self.session.get(f'https://{self.ip}/admin/', headers=csrf_header)

        response = self.session.post(url_csrf, headers=csrf_header, data={})
        if response.status_code == 200:
            if 'CSRF' in response.text:
                token_info = response.text.split(':')
                self.csrf_token = {token_info[0]: token_info[1]}

        if self.login_type == 'text':
            url_login = f"https://{self.ip}/admin/LoginAction.do"
            login_payload = f"username={self.user}" \
                            f"&password={self.password}" \
                            f"&samlLogin=false" \
                            f"&rememberme=on" \
                            f"&name={self.user}" \
                            f"&password={self.password}" \
                            f"&authType={self.auth_source}" \
                            f"&newPassword=" \
                            f"&destinationURL=" \
                            f"&CSRFTokenNameValue={token_info[0]}%3D{token_info[1]}" \
                            f"&OWASP_CSRFTOKEN={token_info[1]}" \
                            f"&locale=en&" \
                            f"hasSelectedLocale=false" \
                # f"&isPreLoginBannerAccepted=true"
        else:
            url_login = f"https://{self.ip}/admin/"
            login_payload = "preloginbanner=displayed"
            self.session.mount(f"https://{self.ip}", Pkcs12Adapter(pkcs12_filename=self.cert_location, pkcs12_password=self.cert_passwd))

        login_header = self.HEADER_DATA.copy()
        login_header['Referer'] = 'https://10.11.6.10/admin/'
        login_header['Content-Type'] = 'application/x-www-form-urlencoded'
        response = self.session.post(url_login, data=login_payload, headers=login_header, verify=False, allow_redirects=True)
        if response.status_code == 200:
            if 'lastLoginSuccess' in response.text:
                self.HEADER_DATA.update(self.csrf_token)
                self.logger.debug('CSRF TOKEN Obtained')
                self.logger.info('Authentication Successful')
                return True
        self.logger.critical('Authentication Failed, Please Check Configuration and Try Again')
        quit()

    def logout_ise_session(self):
        self.session.get(f'https://{self.ip}/admin/logout.jsp')

    def get_all_endpoint_data(self):
        endpoints = []
        step_page = 1
        control_size = 500
        while True:
            # step thru endpoint pages
            search_field = f'status=CONTEXT_EXTACT_MATCH_connected' \
                           f'&columns=' \
                           f'&sortBy=MACAddress' \
                           f'&startAt={step_page}' \
                           f'&pageSize={control_size}' \
                           f'&total_pages=5000' \
                           f'&total_entries={control_size}'
            if not bool(self.config.get('only_connected')):
                search_field = search_field.replace('status=CONTEXT_EXTACT_MATCH_connected&', '')

            # change header for search params
            header = self.HEADER_DATA.copy()
            header['_QPH_'] = self.UTILS.encode_data(search_field)
            response = self.session.get(f'https://{self.ip}/admin/rs/uiapi/visibility', headers=header)

            if response.status_code == 200:
                ep_data = response.json()
                if len(ep_data) > 0:
                    endpoints = endpoints + ep_data
                    step_page += 1
                else:
                    break
            else:
                self.logger.critical(f'received HTTP CODE {response.status_code} terminating')
                raise RuntimeError

        # clean list and transform json str to dicts to load into DF
        endpoints = list(set(endpoints))
        endpoints = [json.loads(epd) for epd in endpoints]
        self.logger.info(f'Gathered {len(endpoints)} endpoints from ISE')
        self.endpoints = pd.DataFrame(endpoints)

    def get_endpoint_data(self, mac_address,pbar_func=None):
        self.logger.debug(f'spawning new process for endpoint_data on {getpid()}')
        # Mac addr must be 11:11:11:11:11:11 notation
        response = self.session.get(f'https://{self.ip}/admin/rs/uiapi/visibility/endpoint/{mac_address}', headers=self.HEADER_DATA)
        # if we are using progress bar increment it
        if pbar_func:
            pbar_func.update(1)
        if response.status_code == 200:
            ep_info = response.json()
            return ep_info
        self.logger.debug(f'Could not receive data for mac address: {mac_address}')

    def get_metadata_from_endpoints(self, specific: str = False):
        pbar = tqdm(desc='Getting Endpoint Metadata',total=len(self.endpoints['MACAddress']),colour='red')
        try:
            if specific:
                self.endpoints[specific] = self.endpoints['MACAddress'].apply(lambda x: self.get_endpoint_data(x,pbar).get(specific))
            else:
                # gather macs and get all attr from them
                ep_name_list = self.endpoints['MACAddress'].to_list()
                ep_data = [self.get_endpoint_data(i,pbar) for i in ep_name_list]
                self.endpoints = pd.DataFrame(ep_data)
        except Exception as execpt_error:
            self.logger.debug(f'META_PILL_ERROR: {execpt_error}')
            if specific:
                self.endpoints[specific] = self.endpoints['Calling-Station-ID'].apply(lambda x: self.get_endpoint_data(x,pbar).get(specific))
            else:
                # gather macs and get all attr from them
                ep_name_list = self.endpoints['Calling-Station-ID'].to_list()
                ep_data = [self.get_endpoint_data(i,pbar) for i in ep_name_list]
                self.endpoints = pd.DataFrame(ep_data)
        pbar.close()
        self.endpoints.replace({None: 'unknown'}, inplace=True)

    def get_license_info(self):
        self.logger.debug('Collecting primary node SN')
        header = self.HEADER_DATA.copy()

        license_field = 'command=loadSlConfigDetail&dojo.preventCache=1664971537253'
        header['_QPH_'] = self.UTILS.encode_data(license_field)
        header['Content-Type'] = 'application/x-www-form-urlencoded'

        response = self.session.get(f'https://{self.ip}/admin/licenseAction.do', headers=header)
        if response.status_code == 200:
            license_data = response.json()
            self.logger.info('Obtained Device Serial Number')
            return license_data['serialNo']
        self.logger.debug(f'Could not obtain primary node SN - Received HTTP status code:{str(response.status_code)}')

    def get_endpoint_software_info(self):
        # applications data
        host_sw = 'pageType=app&columns=productName%2Cversion%2CvendorName%2Ccategories%2CoperatingSystem%2CnoOfDevicesPerApp&sortBy=productName&startAt=1&pageSize=10000'
        # transform to base64 then into the str representation of it
        host_sw = base64.b64encode(str.encode(host_sw)).decode('utf-8')
        # session cookie are persistence so only need to add this header that was implemented from the JS caller
        headers = {'_QPH_': host_sw}
        url = f"https://{self.ip}/admin/rs/uiapi/visibility"
        self.sw_catalog = self.session.get(url, headers=headers)

    def get_endpoint_hardware_info(self, mac_address, high_level=False):
        url = f"https://{self.ip}/admin/rs/uiapi/hwvisibility"
        if not high_level:
            # can only get data one at a time per mac
            header_data = f'columns=NoOfDevicesPerHw%2CMACAddress&sortBy=name&MACAddress={mac_address}&startAt=1&pageSize=10000'
        else:
            header_data = 'pageType=hw&' \
                          'columns=MACAddress,manufacture,serialNum,noOfAttachments,cpuUsage,memoryUsage,hdUsage,NAS-Port-Id,status,NetworkDeviceName,PhoneID,ip&' \
                          'sortBy=MACAddress&' \
                          'startAt=1&' \
                          'pageSize=10&' \
                          'total_pages=1&' \
                          'total_entries=1'

        # transform to base64 then into the str representation of it
        header_data = base64.b64encode(str.encode(header_data)).decode('utf-8')
        # session cookie are persistence so only need to add this header that was implemented from the JS caller
        header = self.HEADER_DATA.copy()
        header['_QPH_'] = header_data
        response = self.session.get(url, headers=header)
        # so we dont break compability with old caller in report_data
        if not high_level:
            return response

        if response.status_code == 200:
            hw_data = json.loads(response.json()[0])
            return hw_data
        self.logger.debug(f'Could not receive data for mac address: {mac_address}')

    def special_reporting_data(self):
        special_rep = self.config['special_reporting']
        reporting_location = special_rep.get('reporting_location')
        find_files = special_rep.get('files_to_look_for')
        filter_list = special_rep.get('filter_list')
        special_items = special_rep.get('filter_specifics')
        attr_to_look_for = special_rep.get('get_attribute_from_endpoint')
        fnames = self.UTILS.get_files_from_loc(reporting_location, find_files)
        # df holder
        self.endpoints = pd.DataFrame([])
        for f in fnames:
            ep_df = pd.read_csv(f'{reporting_location}/{f}')
            ep_df = self.filter_data(ep_df, filter_list, special_items)
            self.endpoints = pd.concat([self.endpoints, ep_df], ignore_index=True)
            self.UTILS.create_file_path('archive', f, parent_dir=reporting_location)
        self.get_metadata_from_endpoints(attr_to_look_for)
        self.logger.info('Endpoint special data collection complete')

    def join_hw_data(self):
        try:
            ep_name = self.endpoints['Calling-Station-ID'][self.endpoints['PostureReport'] != 'unknown'].tolist()
        except Exception as error:
            self.logger.exception(f'somethings wrong with the dataframe....:\n {error} \n\n QUITING')
            self.logout_ise_session()
            return
        hw_data = [self.get_endpoint_hardware_info(i.replace('-',':'),high_level=True) for i in ep_name]
        hw_data = pd.DataFrame(hw_data)
        # conform hw data to match self endpoints so we can merge them
        hw_data.rename(columns={'MACAddress':'Calling-Station-ID'},inplace=True)
        # since we might not have anything in the df lets error check and if it doesnt skip hw processing
        try:
            hw_data['Calling-Station-ID'] = hw_data['Calling-Station-ID'].apply(lambda x: x.replace(':','-'))
            self.endpoints = pd.concat([self.endpoints, hw_data], axis=1)
            self.endpoints.replace({None: 'unknown'}, inplace=True)
        except Exception as error:
            self.logger.exception(f'somethings wrong with the dataframe....:\n {error} \n\n QUITING')
            return

    def filter_data(self, raw_df: pd.DataFrame, filter_list: list, data_matching: dict = None):
        raw_df.drop(columns=filter_list, inplace=True)
        # if we have specifics we want to match on
        if data_matching:
            for k, v in data_matching.items():
                # try to see if we fit a usecase if not keep going
                try:
                    raw_df = raw_df[raw_df[k].astype(int) > v]
                    continue
                except Exception as error:
                    self.logger.debug(error)

                try:
                    raw_df = raw_df[raw_df[k].str.contains(v)]
                    continue
                except Exception as error:
                    self.logger.debug(error)
        return raw_df

    def retrieve_endpoint_data(self):
        # deployment ID
        self.sn = self.get_license_info()
        self.endpoint_policies = None
        self.logger.debug('Collecting endpoint data')
        self.get_all_endpoint_data()
        # pull N or all
        if bool(self.config.get('test_endpoint_pull')):
            self.logger.info(f'Sample Size of {self.config.get("test_endpoint_pull")} Endpoints being used.')
            self.endpoints = self.endpoints.loc[:self.config.get('test_endpoint_pull')]

        # since we dont need that much info in step 1 just pull the logical profile else pull all data
        if self.config['ComplytoConnect']['phase'] == 1:
            self.get_metadata_from_endpoints(specific='LogicalProfile')
        elif self.config['ComplytoConnect']['phase'] == 2:
            self.get_metadata_from_endpoints()
            # need to get hardware serials also
            self.join_hw_data()
        # since Clarity doesn't de-conflict logical profiles when two logical profiles are assigned to the same endpoint, take the first res. for more see FAQ
        self.endpoints['LogicalProfile'] = self.endpoints['LogicalProfile'].apply(lambda x: x.split(',')[0])
        self.logger.info('Endpoint data collection complete')
        self.logout_ise_session()


if __name__ == '__main__':
    ise = Clarity()
    ise.retrieve_endpoint_data()
