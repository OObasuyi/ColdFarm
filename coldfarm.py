from requests import Session
from json import loads, dumps
from utils import log_collector, Rutils
import pandas as pd



class ColdSore:
    UTILS = Rutils()

    def __init__(self, config: str = "config.yaml", verify_ssl=False):
        self.logger = log_collector(file_name='hazbag.log', func_name='ColdSore')
        # move config file to new folder
        config = self.UTILS.create_file_path('configs', config)
        self.config = self.UTILS.get_yaml_config(config, self)
        self.ssl_verify = verify_ssl

    
    def pull_tenable_info(self):
        tenable_info = self.config['TENABLE']
        tenable_session = Session()
        tenable_session.verify = self.ssl_verify
        tenable_session.headers = {"Accept": "application/json", "Content-Type": "application/json"}
        tenable_session.headers["x-apikey"] = f"accesskey={tenable_info['accesskey']}; secretkey={tenable_info['secretkey']}"
        score_data_url = f'{tenable_info["node"]}/rest/analysis'
        sc_pd = pd.DataFrame([]) # holder

        req_score_data = {
            "type": "vuln",
            "query": {"id": tenable_info['query_id']},
            "sourceType": "cumulative"
        } 
        # pull data from SC
        data_req = tenable_session.post(score_data_url, data=dumps(req_score_data))
        if data_req.status_code != 200:
            self.logger.critical(f'tenable: could not reach node at {score_data_url}')
            self.logger.critical(f'tenable: code recvd from node {data_req.status_code} \n\n CONTENT:\n\n\ {data_req.content}\n\n')
            self.logger.critical(f'tenable: QUITTING PROGRAM!!!!!!')
            quit()
        else:
            sc_dat = loads(data_req.content).get("response").get('results')
        
        sc_pd = pd.DataFrame(sc_dat)
        # normalize and remove unneeded.
        return sc_pd

#TODO: need to make ISE customattr for last time scanned and severity
    def pull_ise_info(self):
        ise_info = self.config['ISE']
        ise_session = Session()
        ise_session.verify = self.ssl_verify
        ise_session.headers = {"Accept": "application/xml", "Content-Type": "application/xml"}
        ise_session.auth = (ise_info['username'], ise_info['password'])
        mnt_data_url = f'{ise_info["node"]}/admin/API/mnt/Session/ActiveList'
        ise_data = pd.DataFrame([]) # holder

        data_req = ise_session.get(mnt_data_url)
        if data_req.status_code != 200:
            self.logger.critical(f'ise: could not reach node at {mnt_data_url}')
            self.logger.critical(f'ise: code recvd from node {data_req.status_code} \n\n CONTENT:\n\n\ {data_req.content}\n\n')
            self.logger.critical(f'ise: QUITTING PROGRAM!!!!!!')
            quit()
        else:
            ise_data = pd.read_xml(data_req.content,parser='etree')
        
        ise_data.rename(columns={"calling_station_id":"macAddress"},inplace=True)
        return ise_data

    @staticmethod
    def combine_ise_tenable(ise_pd,sc_pd):
        combined_df = pd.concat([ise_pd, sc_pd], axis=0).drop_duplicates(subset=['macAddress'])
        return combined_df

    def push_to_ise(self):

        ten_pd= self.pull_tenable_info()
        ise_pd= self.pull_ise_info()
        combined_data = self.combine_ise_tenable(ise_pd,ten_pd)
        # drop spots with no mac since thats a key feature for ISE
        combined_data.dropna(subset=['acrScore','server'],inplace=True)
        #TODO: not finding anything in common??????
        pass





if __name__ == "__main__":
    coldS = ColdSore('config_test.yaml')
    coldS.push_to_ise()
