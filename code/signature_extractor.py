from pandas.core.frame import DataFrame
from address_mapper import Mapper
from pandas.core import groupby
from datetime import datetime
from netaddr import *

import pandas as pd
import numpy as np
import warnings
import pyshark
import utils
import glob
import os

class SignatureExtractor():

    def __init__(self, df: DataFrame=None):
        self.df = df
        self.signatures = {'signatures': [], 'gap': []}
        self.thresh_packets = 2
        
    #--------------- Helper functions ---------------#

    # Time grouper a replica of packet analyzer function
    def timed_grouper(self, row, seconds=1, custom=None):
        self.group_category =  (self.group_category + 1) \
                                if row['Timestamp'] - self.group_category_time > seconds \
                                else self.group_category
        if self.group_category_time != row['Timestamp']:
            self.group_category_time = row['Timestamp']
            
        return self.group_category

    # Helper function
    def compare_groups(self, g1, g2, sorted_g1, sorted_g2):
        g1_packets = len(g1)
        g2_packets = len(g2)
        
        eq = (g1[self.cols] == g2[self.cols]).all(axis=1)
        same_packets = len(eq[eq == True])

        sorted_eq = (sorted_g1 == sorted_g2).all(axis=1)
        sorted_same_packets = len(sorted_eq[sorted_eq == True])

        if  (same_packets == g1_packets) or \
            (   g1_packets > 4 and 
                sorted_same_packets == g2_packets and 
                same_packets + self.thresh_packets >= g2_packets
            ):
            return True
            
        return False

    #--------------- END ---------------#

    # Works in a similar way as packet analyzer function
    def process_data(self):
    
        # drop duplicate packets
        self.df.drop_duplicates([   'Timestamp', 'Source', 'Destination', 
                                    'Payload_length', 'Sequence_number'], keep='first', inplace=True)
        
        m = self.df.groupby(['Source', 'Destination', 'Payload_length', 'Sequence_number']).Timestamp.apply(lambda x: x.diff() < 2)
        self.df = self.df[~m]

        if len(self.df):
            # Set bursts
            self.group_category = 1
            self.group_category_time = self.df['Timestamp'][0]
            self.df['Burst'] = self.df.apply(lambda x: self.timed_grouper(x), axis=1)

            # Reset index
            self.df = self.df.reset_index().drop(columns=['index'])            
        else:
            print("Empty file!")

        return self.df

    # Signatures fetched are further cleaned to remove duplicates or those with almost similar order are combined into one
    def signatures_cleaner(self):

        # Not considering GAP in cleaning
        sig = self.signatures['signatures']
        gap = self.signatures['gap']

        for i, sig1 in enumerate(sig):
            if sig1 is None:
                continue

            for j in range(i+1, len(sig)):
                sig2 = sig[j]

                if sig2 is None:
                    continue

                sig_1_packets = len(sig1)
                sig_2_packets = len(sig2)

                if sig_1_packets == sig_2_packets:# and sig_1_packets > 4:
                    eq = (sig1[self.cols] == sig2[self.cols]).all(axis=1)
                    eq = (sig1[self.cols].sort_values([ 'Payload_length'], 
                                                        ignore_index=True) == sig2[self.cols].sort_values([ 'Payload_length'], 
                                                                                                            ignore_index=True)).all(axis=1)
                    same_packets = len(eq[eq == True])
                    if same_packets == sig_1_packets:
                        sig[j] = None
                        gap[j] = None
                        continue

                combo_sig = pd.concat([sig1, sig2])
                combo_sig.reset_index(drop=True, inplace=True)

                for k in range(j+1, len(sig)):
                    sig3 = sig[k]

                    if j == k or i == k or sig3 is None:
                        continue
                    
                    if len(sig3) == len(combo_sig) and (sig3[self.cols] == combo_sig[self.cols]).all(axis=1).all():
                        combo_temp = combo_sig.drop_duplicates([self.key])

                        gap[i] = sig3['Timestamp'][combo_temp.index[0]] - combo_temp['Timestamp'].iloc[0]
                        gap[j] = sig3['Timestamp'][combo_temp.index[-1]] - combo_temp['Timestamp'].iloc[-1]

                        sig[k] = None
                        gap[k] = None

    # This extracts the signature from the main dataframe
    def extract_signatures(self):
        
        # Check if the file is of Philips or not (src: ZR and dst: ZR)
        zr_device_df = self.sig_df[ (self.sig_df['Src_device'].str.contains('ZR')) & 
                                    (self.sig_df['Dst_device'].str.contains('ZR'))]

        self.sig_df = zr_device_df.copy() if len(zr_device_df) > 1 else self.sig_df

        self.key = 'Timestamp' if len(zr_device_df) > 1 and not utils.checker(self.sig_df) else 'Burst'

        # Group based on key (burst or timestamp if device is philips)
        self.group_sig = self.sig_df.groupby(self.key)[self.sig_df.columns]

        for _, group1 in self.group_sig:
            for _, group2 in self.group_sig:
                group1 = group1.copy()
                group2 = group2.copy()

                group1_packets = len(group1)
                group2_packets = len(group2)
                group1.index = np.arange(0, group1_packets)
                group2.index = np.arange(0, group2_packets)

                if group1[self.key].iloc[0] < group2[self.key].iloc[0] and group1_packets == group2_packets:
                    gap = group2['Timestamp'].iloc[0] - group1['Timestamp'].iloc[0]
                    eq = (group1[self.cols] == group2[self.cols]).all(axis=1)

                    sorted_group1 = group1[self.cols].sort_values(['Payload_length'], ignore_index=True)
                    sorted_group2 = group2[self.cols].sort_values(['Payload_length'], ignore_index=True)

                    same_packets = len(eq[eq == True])

                    low_gap = int(gap - 14)
                    high_gap = int(gap + 14)

                    if not any( group2_packets == len(sig) and (group1[self.cols] == sig[self.cols]).all(axis=1).all() 
                                for sig in self.signatures['signatures']):

                        if  same_packets == group2_packets or \
                            (group1_packets > 4 and self.compare_groups(group1, group2, sorted_group1, sorted_group2)):


                            if gap >= 3500:
                                self.signatures['signatures'].append(group1)
                                self.signatures['gap'].append(gap)
                            else:
                                # Final: check again if burst exists after that gap than accept it
                                groups_to_check = self.sig_df[
                                                                (self.sig_df['Timestamp'] > (group2['Timestamp'].iloc[0] + low_gap)) & 
                                                                (self.sig_df['Timestamp'] < (group2['Timestamp'].iloc[0] + high_gap))
                                                            ][self.key].unique()
                                                            
                                for k in groups_to_check:
                                    group3 = self.sig_df[self.sig_df[self.key] == k].copy()
                                    group3.index = np.arange(0, len(group3))

                                    if len(group3) != len(group2):
                                        continue # changed from break

                                    sorted_group3 = group3[self.cols].sort_values(['Payload_length'], ignore_index=True)

                                    if self.compare_groups(group2, group3, sorted_group2, sorted_group3):
                                        self.signatures['signatures'].append(group1)
                                        self.signatures['gap'].append(gap)

                            break

    def start_extractor(self, mapper: Mapper, sig_df: DataFrame=None):
        
        self.sig_df = self.df.copy() if sig_df is None else sig_df

        # Get average time of data requests of each address (ZED device)
        # NOTE: not in use anymore
        # data_requests_avg = mapper.get_data_request_difference()  # Postponed for now

        # Get relevant columns for searching
        remove_columns = ['Time', 'Timestamp', 'Sequence_number', 'Src_device', 'Dst_device', 'Burst', 'Packet_length']
        self.cols = [col for col in self.sig_df.columns if col not in remove_columns]

        if self.sig_df is None:
            return self.signatures
        elif not len(self.sig_df):
            return self.signatures

        self.extract_signatures()
        self.signatures_cleaner()

        self.signatures['signatures'] = [df for df in self.signatures['signatures'] if df is not None]
        self.signatures['gap'] = [gap for gap in self.signatures['gap'] if gap is not None]

        for k, sig in enumerate(self.signatures['signatures']):
            sig['Gap'] = self.signatures['gap'][k]

        return self.signatures

def extract_data(pcapfile, addr=None):
    
    display_filter = f'(zbee_nwk.frame_type == 0 && zbee_nwk.addr == {addr})' if addr else '(zbee_nwk.frame_type == 0)'

    pcap = pyshark.FileCapture(pcapfile, display_filter=display_filter)#+rules)

    try:
        packets =  {
                            'Timestamp': [int(float(packet.frame_info.time_epoch)) for packet in pcap],

                            'Time': [datetime.fromtimestamp(int(float(packet.frame_info.time_epoch))) for packet in pcap],
                            # Check source addr from zbee_nwk if doesnt exist
                            # then use wpan source addr
                            'Source': [ packet.zbee_nwk.src 
                                        if 'zbee_nwk' in packet 
                                        else 
                                        packet.wpan.src16
                                        if 'src16' in packet.wpan.field_names
                                        else None
                                        for packet in pcap],

                            # Check dest addr from zbee_nwk if doesnt exist
                            # then use wpan dest addr
                            'Destination': [packet.zbee_nwk.dst if 'zbee_nwk' in packet 
                                            else 
                                            packet.wpan.dst16
                                            if 'dst16' in packet.wpan.field_names
                                            else None
                                            for packet in pcap],
                            
                            'Packet_length': [int(packet.frame_info.len) for packet in pcap],

                            # If zbee_nwk layer is in the packet then fetch the packet length
                            'Payload_length': [  int(packet.zbee_nwk.data_len)
                                                if 'zbee_nwk' in packet
                                                else None
                                                for packet in pcap],
                            
                            # Ignore seq num if no zbee_nwk layer
                            'Sequence_number': [packet.zbee_nwk.seqno
                                                if 'zbee_nwk' in packet
                                                else None
                                                for packet in pcap],

                            # Ignore mac addr if no zbee_nwk layer
                            'Mac': [packet.zbee_nwk.zbee_sec_src64
                                    if 'zbee_nwk' in packet
                                    else None
                                    for packet in pcap],
                        }

    except:
        pass
    finally:
        pcap.close()

    return packets

def signatures_csv_generator(filename, signatures):
    
    if not os.path.exists("signatures"):
        os.mkdir("signatures")

    os.chdir(os.path.join(os.getcwd(), "signatures"))

    folder_name = filename.split('.')[0] + "_signatures"

    if not os.path.exists(folder_name):
        os.mkdir(folder_name)

    for k, sig in enumerate(signatures['signatures']):
        path = os.path.join(folder_name, f"{k}.csv")
        sig.to_csv(path, index=False)

    os.chdir('..')

def start(pcapfile):

    print('Filename:', pcapfile)

    packets = extract_data(pcapfile)
    main_df = pd.DataFrame(packets)

    extractor = SignatureExtractor(main_df)
    mapper = Mapper(main_df)
    devices = mapper.fetch_device_types(pcapfile)
    addresses, man_dict = mapper.get_all_devices(pcapfile)
    main_df = mapper.add_device_type_to_data()

    if not os.path.exists("uncleaned"):
        os.mkdir("uncleaned")

    uncleaned_files_path = os.path.join(os.getcwd(), 'uncleaned')

    main_df = extractor.process_data()
    main_df.to_csv(os.path.join(uncleaned_files_path, f"uncleaned_{pcapfile.split('.')[0]}.csv"), index=False)

    # Extract signatures
    signatures = None
    signatures = extractor.start_extractor(mapper)

    signatures_csv_generator(pcapfile, signatures)

    print(f'{len(signatures["signatures"])} Signatures extracted')
    
def main():
    for pcapfile in glob.glob("*.pcapng") + glob.glob("*.pcap"):
        start(pcapfile)


if __name__ == '__main__':
    warnings.filterwarnings("ignore")
    broadcast_addresses = ['0x0000fffc', '0x0000fffd', '0x0000ffff']
    main()