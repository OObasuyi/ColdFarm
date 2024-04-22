from argparse import ArgumentParser
from coldfarm import Farm


def term_access():
    parser = ArgumentParser(prog='coldFarm.py', description='ColdFarm')
    cold_args = parser.add_argument_group(title='ColdFarm Fields')
    cold_args.add_argument('--config_file', help='location of config file', default='config.yaml', type=str)
    cold_args.add_argument('--test_count', help='FOR TESTING ONLY. choose a minimal amount test endpoints to generate and send to ISE! ', default=0, type=int)
    cold_args.add_argument('--test_seed', help='FOR TESTING ONLY. if want test endpoints to be random pick a number', default=None, type=int)
    args = parser.parse_args()

    agg_data_to_ise = Farm(config=args.config_file)
    agg_data_to_ise.send_data_to_ise(test_data=args.test_count, test_seed=args.test_seed)


if __name__ == '__main__':
    term_access()
