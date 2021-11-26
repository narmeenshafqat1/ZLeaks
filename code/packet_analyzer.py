from pandas.core.frame import DataFrame
from address_mapper import Mapper
from comparator import Comparator
from datetime import datetime
from netaddr import *

import pandas as pd
import numpy as np
import warnings
import pyshark
import utils
import glob
import os


class PackerAnalyser():

    def __init__(self, df: DataFrame=None):
        self.df = df

    #--------------- Grouper functions ---------------#

    # Creating Custom Grouper based on each usage
    def timed_grouper(self, row, seconds=1, custom=None):
        self.group_category =  (self.group_category + 1) \
                                if row['Timestamp'] - self.group_category_time > seconds \
                                else self.group_category
        if not custom and self.group_category_time != row['Timestamp']:
            self.group_category_time = row['Timestamp']
        elif self.group_category_time != row['Timestamp'] and custom(row):
            self.group_category_time = row['Timestamp']
  
        return self.group_category

    def timed_grouper_10_sec(self, row):
        
        self.group_category =  (self.group_category + 1) \
                                if row['Timestamp'] - self.group_category_time > 10 \
                                else self.group_category

        if self.group_category_time != row['Timestamp'] and (row['Payload_length'] == 28 and row['Packet_length'] == 65):
            self.group_category += 1
            self.group_category_time = row['Timestamp']
                                
        return self.group_category

    def timed_grouper_20_sec(self, row):

        if self.first:
            self.num_of_bursts = [0, row['Burst']]
            self.first = False
        if self.num_of_bursts[-1] != row['Burst']:
            self.num_of_bursts[0] += 1
            self.num_of_bursts[-1] = row['Burst']

        if self.num_of_bursts[0] == 2:
            self.num_of_bursts[0] = 0
            self.group_category += 1
            self.group_category_time = row['Timestamp']
            return self.group_category    

        if row['Timestamp'] - self.group_category_time > 20:
            self.num_of_bursts[0] = 0
            self.group_category += 1

        if self.group_category_time != row['Timestamp']:
            self.group_category_time = row['Timestamp']
                                
        return self.group_category

    #--------------- END ---------------#

    #--------------- helper functions ---------------#

    def create_bursts(self, row):
        self.burst_category =   (self.burst_category + 1) \
                                if row['Timestamp'] - self.burst_category_time > 1 \
                                else self.burst_category
        self.burst_category_time = row['Timestamp'] if self.burst_category_time != row['Timestamp'] else self.burst_category_time
        return self.burst_category
    
    # Detect sensor packets
    def detect_sensor_type(self, x):

        cd_54_17 = x[(x['Payload_length'] == 17) & (x['Packet_length'] == 54) & x['Src_device'].str.contains('ZC')]
        dc_54_17 = x[(x['Payload_length'] == 17) & (x['Packet_length'] == 54) & x['Dst_device'].str.contains('ZC') & (x['DR_Avg_Time'] < 60.0)]
        cd_48_11 = x[(x['Payload_length'] == 11) & (x['Packet_length'] == 48) & x['Src_device'].str.contains('ZC')]

        if len(dc_54_17) and not len(cd_54_17) and not len(cd_48_11):
            sensor_packets = len(dc_54_17)

            if sensor_packets == 3:
                return "Audio Sensor"
            if sensor_packets == 2:
                return "Flood Sensor"
            if sensor_packets == 1:
                return "Motion Sensor|Door Sensor"
        return None

    # Detect lock packets
    def detect_lock_packets(self, x):
        if  len(x[(x['Payload_length'] == 11) & (x['Packet_length'] == 48) & x['Dst_device'].str.contains('ZED')]) > 0 and \
            len(x[(x['Payload_length'] == 12) & (x['Packet_length'] == 49) & x['Dst_device'].str.contains('ZC')]) > 0:
            return 'Locks'
    
    # Detect "bulb on" packets
    def detect_bulb_on_packets(self, x):

        jk_48_11 = x[   (x['Payload_length'] == 11) & (x['Packet_length'] == 48) & (x['Src_device'].str.contains('ZR')) & 
                        (x['Dst_device'].str.contains('ZR'))]

        jb_12 = x[  (x['Payload_length'] == 12) & (x['Src_device'].str.contains('ZR')) &
                    (x['Destination'] == '0x0000fffd')]

        jb_14 = x[  (x['Payload_length'] == 14) & (x['Src_device'].str.contains('ZR')) &
                    (x['Destination'] == '0x0000fffd')]

        if len(jk_48_11):
            src = jk_48_11['Source'].iloc[0]
            dst = jk_48_11['Destination'].iloc[0]

            kj_62_25 = x[(x['Payload_length'] == 25) & (x['Packet_length'] == 62) & (x['Src_device'].str.contains('ZR')) & 
                        (x['Dst_device'].str.contains('ZR')) & (x['Source'] == dst) & (x['Destination'] == src)]

            kj_52_15 = x[(x['Payload_length'] == 15) & (x['Packet_length'] == 52) & (x['Src_device'].str.contains('ZR')) & 
                        (x['Dst_device'].str.contains('ZR')) & (x['Source'] == dst) & (x['Destination'] == src)]

            kb_20 = x[  (x['Payload_length'] == 20) & (x['Src_device'].str.contains('ZR')) & (x['Source'] == dst) & 
                        ((x['Destination'] == '0x0000fffc') | (x['Destination'] == '0x0000fffd') | (x['Destination'] == '0x0000ffff'))]

            if not (len(kj_62_25) or len(kj_52_15) or len(kb_20)):
                self.bulb_on.add(x.iloc[0, 0])  # Timestamp

        if len(jb_12):
            self.bulb_on.add(x.iloc[0, 0])

        if len(jb_14):
            self.bulb_off.add(x.iloc[0, 0])

    # Detect bulb/plugin packets
    def detect_bulb_packets(self, x):

        x = x.copy()
            
        # Rule 4
        if not utils.checker(x):
            x.groupby('Timestamp').apply(lambda x: self.detect_bulb_on_packets(x))

        # Convert 0x00000001, 0x00000002, 0x00000003, 0x00000004, 0x00000005 bridging devices to ZC if they exist
        for i, row in x.iterrows():
            if  str(row['Source']) == '0x00000001' or \
                str(row['Source']) == '0x00000002' or \
                str(row['Source']) == '0x00000003' or \
                str(row['Source']) == '0x00000004' or \
                str(row['Source']) == '0x00000005':
                x.at[i, 'Src_device'] = 'ZC'

            if  str(row['Destination']) == '0x00000001' or \
                str(row['Destination']) == '0x00000002' or \
                str(row['Destination']) == '0x00000003' or \
                str(row['Destination']) == '0x00000004' or \
                str(row['Destination']) == '0x00000005':
                x.at[i, 'Dst_device'] = 'ZC'

        cd_48_11 = x[(x['Payload_length'] == 11) & (x['Packet_length'] == 48) & x['Src_device'].str.contains('ZC')]
        dc_49_12 = x[(x['Payload_length'] == 12) & (x['Packet_length'] == 49) & x['Dst_device'].str.contains('ZC')]
        cd_51_14 = x[   (x['Payload_length'] == 14) & (x['Packet_length'] == 51) & x['Src_device'].str.contains('ZC') &
                        (x['Discovery'] == "0x00000001")]
        db_54_17 = x[(x['Payload_length'] == 17) & (x['Packet_length'] == 54) &
                    ((x['Destination'] == '0x0000fffc') | (x['Destination'] == '0x0000fffd') | (x['Destination'] == '0x0000ffff'))]
        cd_50_11 = x[(x['Payload_length'] == 11) & (x['Packet_length'] == 50) & x['Src_device'].str.contains('ZC')]
        cd_52_11 = x[(x['Payload_length'] == 11) & (x['Packet_length'] == 52) & x['Src_device'].str.contains('ZC')]
        db_20 = x[  (x['Payload_length'] == 20) & 
                    ((x['Destination'] == '0x0000fffc') | (x['Destination'] == '0x0000fffd') | (x['Destination'] == '0x0000ffff'))]
        cd_dc_13 = x[(x['Payload_length'] == 13) & ((x['Src_device'].str.contains('ZC')) | (x['Dst_device'].str.contains('ZC')))]
        dc_11 = x[(x['Payload_length'] == 11) & (x['Dst_device'].str.contains('ZC'))]
        cd_15 = x[(x['Payload_length'] == 15) & (x['Src_device'].str.contains('ZC'))]
        cd_17 = x[(x['Payload_length'] == 17) & (x['Src_device'].str.contains('ZC'))]
        dc_12 = x[(x['Payload_length'] == 12) & (x['Dst_device'].str.contains('ZC'))]
        dc_15 = x[(x['Payload_length'] == 15) & (x['Dst_device'].str.contains('ZC'))]
        dc_19 = x[(x['Payload_length'] == 19) & (x['Dst_device'].str.contains('ZC'))]
        dc_21 = x[(x['Payload_length'] == 21) & (x['Dst_device'].str.contains('ZC'))]
        dc_23 = x[(x['Payload_length'] == 23) & (x['Dst_device'].str.contains('ZC'))]
        dc_26 = x[(x['Payload_length'] == 26) & (x['Dst_device'].str.contains('ZC'))]

        # Rule 2
        if  ((len(cd_48_11) or len(cd_50_11)) or len(cd_52_11)) and \
            not len(dc_49_12) and \
            not len(db_20) and \
            (len(cd_dc_13) or len(dc_15)):

            if len(cd_15):
                return 'Bulb color control'
            return 'Bulb|Plug'

        if len(cd_15) and not (len(dc_12) or len(db_20)) and (len(dc_19) or len(dc_21) or len(dc_23) or len(dc_26)):
            return 'Bulb color control'

        # Rule 3
        if  len(cd_51_14) and \
            not len(db_54_17) and \
            not len(dc_11):
            return "Bulb level control"

        return None

    # Detects motion sensor packets
    def check_similar_packets(self, x):
        burst_to_check = x.drop_duplicates(['Burst'], keep='first')
        bursts_in_group = len(burst_to_check)
        burst_values = burst_to_check['Burst'].values

        packets_in_burst = [(   len(x[x['Burst'] == burst_to_check['Burst'].iloc[b]]), x[x['Burst'] == burst_values[b]].index) 
                                for b in range(bursts_in_group)]
        
        if bursts_in_group == 2:
            bool_motion_sensor = x[['Source',
                                    'Destination', 
                                    'Payload_length', 
                                    'Packet_length', 
                                    'Mac']] \
                                    .isin(burst_to_check[[  'Source', 
                                                            'Destination', 
                                                            'Payload_length', 
                                                            'Packet_length', 
                                                            'Mac']].to_dict('list')).all(axis=1)

            true_bool_motion_sensor = len(bool_motion_sensor[bool_motion_sensor == True])

            if true_bool_motion_sensor <= packets_in_burst[-1][0] :
                self.sensor_df['Sensor'][packets_in_burst[0][-1]] = 'Motion Sensor'
                self.sensor_df['Sensor'][packets_in_burst[1][-1]] = 'Motion Sensor Rec'

    # Packet detected by this function are report packets not sensor event
    def check_conflicting_packets(self, x):
        packet_type_one = x[(x['Payload_length'] == 28) & (x['Packet_length'] == 65)]
        packet_type_two = x[(x['Payload_length'] == 17) & (x['Packet_length'] == 54)]

        if len(packet_type_one) > 0 and len(packet_type_two) > 0 and (packet_type_two.iloc[0, 0] > packet_type_one.iloc[0, 0]):
            return set(packet_type_two['Burst'].values)

    # Set remaining Motion Sensor|Door Sensor to Door Sensor
    def set_door_sensor(self, x):
        self.sensor_df['Sensor'][x.name] = 'Door Sensor'

    #--------------- END ---------------#

    # Processing Sensor data
    def clean_df(self):
        ### Remove burst with broadcast where DB(54, 17)
        #
        group_burst = self.sensor_df.groupby('Burst')

        # broadcast_group = group_burst.apply(lambda x: x[(   x['Destination'] == '0x0000fffd') & 
        #                                                     x['Payload_length'] == 17])
        broadcast_group = group_burst.apply(lambda x: x[x['Destination'] == '0x0000fffd'])

        if len(broadcast_group):

            broadcast_values = broadcast_group['Burst'].values
            burst_to_delete = self.sensor_df['Burst'].isin(broadcast_values)
            burst_to_delete = burst_to_delete[burst_to_delete == True]

            self.sensor_df.drop(self.df.index[burst_to_delete.index], inplace=True)
        #
        ### END

        ### 10 seconds befor DC(54, 17) if packet is DC(65, 28) discard the specific burst
        #
        report_65_28 = self.sensor_df[(self.sensor_df['Payload_length'] == 28) & (self.sensor_df['Packet_length'] == 65)]
        report_54_17 = self.sensor_df[(self.sensor_df['Payload_length'] == 17) & (self.sensor_df['Packet_length'] == 54)]

        report_65_28.drop_duplicates(['Packet_length', 'Payload_length', 'Burst'], keep='last', inplace=True)
        report_df = pd.concat([report_65_28, report_54_17])

        report_df.sort_values('Timestamp', ascending=True, inplace=True)
        
        if len(report_df):
            self.group_category = 1
            self.group_category_time = report_df.iloc[0, 0]

            report_df['10_sec_group'] = report_df.apply(lambda x: self.timed_grouper_10_sec(x), axis=1)

            burst_values = report_df.groupby('10_sec_group').apply(lambda x: self.check_conflicting_packets(x)).dropna()
            conflicting_packets_burst = {v for st in burst_values.values for v in st}

            self.sensor_df = self.sensor_df[~self.sensor_df['Burst'].isin(conflicting_packets_burst)].copy()
        #
        ### END

    def detect_locks(self):
        
        self.lock_df = self.sensor_df[  (self.sensor_df['Dst_device'] == 'ZED') | 
                                        (self.sensor_df['Src_device'] == 'ZED')].copy()

        # Group based on burst to detect lock packets
        group_lock = self.lock_df.groupby('Burst').apply(lambda x: self.detect_lock_packets(x))
        self.lock_df['Lock'] = group_lock[self.lock_df['Burst']].values if not group_lock.empty else None

        self.lock_df = self.lock_df[self.lock_df['Lock'].notnull()].copy()

        return self.lock_df

    def detect_bulbs(self):
        
        # Create bulb df for analyzing bulbs
        self.bulb_df = self.df.copy()

        self.bulb_on = set()
        self.bulb_off = set()

        # Group based on burst to detect bulb packets
        group_bulb = self.bulb_df.groupby('Burst').apply(lambda x: self.detect_bulb_packets(x))
        self.bulb_df['Bulb'] = group_bulb[self.bulb_df['Burst']].values if not group_bulb.empty else None

        for k, b in enumerate(self.bulb_on):
            # self.bulb_df.loc[self.bulb_df['Timestamp'] == b, 'Bulb'] = f"Bulb on_{k}"
            self.bulb_df.loc[self.bulb_df['Timestamp'] == b, 'Bulb'] = f"Bulb on"


        for k, b in enumerate(self.bulb_off):
            # self.bulb_df.loc[self.bulb_df['Timestamp'] == b, 'Bulb'] = f"Bulb off_{k}"
            self.bulb_df.loc[self.bulb_df['Timestamp'] == b, 'Bulb'] = f"Bulb off"

        self.bulb_df = self.bulb_df[self.bulb_df['Bulb'].notnull()].copy()

        return self.bulb_df

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
            print("During Process data: Empty file!")

        return self.df

    def detect_sensor(self):
        
        # Creating another df to analyze sensor data
        # Remove ZR device packets
        self.sensor_df = self.df[self.df['Src_device'] != 'ZR'].copy()
        self.clean_df()

        # Group based on burst to detect sensor packets
        group_sensor_type = self.sensor_df.groupby('Burst').apply(lambda x: self.detect_sensor_type(x))    
        self.sensor_df['Sensor'] = group_sensor_type[self.sensor_df['Burst']].values if not group_sensor_type.empty else None

        # Differentiate between motion sensor or door sensor
        motion_or_door_sensors_df = self.sensor_df[self.sensor_df['Sensor'] == 'Motion Sensor|Door Sensor'].copy()

        if len(motion_or_door_sensors_df):
            self.first = True
            self.group_category = 1
            self.group_category_time = motion_or_door_sensors_df.iloc[0, 0]
            motion_or_door_sensors_df['20_sec_group'] = motion_or_door_sensors_df.apply(lambda x: self.timed_grouper_20_sec(x), axis=1)
            motion_or_door_sensors_df.groupby('20_sec_group').apply(lambda x: self.check_similar_packets(x))

            self.sensor_df[self.sensor_df['Sensor'] == 'Motion Sensor|Door Sensor'].apply(lambda x: self.set_door_sensor(x), axis=1)

        return self.sensor_df

def extract_data(pcapfile, addr=None):
    
    display_filter = f'zbee_nwk.frame_type == 0 && zbee_nwk.addr == {addr}' if addr else 'zbee_nwk.frame_type == 0'
    pcap = pyshark.FileCapture(pcapfile, display_filter=display_filter)

    # Fetches and store all data to packets dictionary
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
                                            
                            'Discovery': [  packet.zbee_nwk.discovery
                                            if 'zbee_nwk' in packet 
                                            and 'discovery' in packet.zbee_nwk.field_names
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
                            
                            # Ignore manufacturer if no zbee_nwk layer
                            # 'Manufacturer': [   EUI(packet.zbee_nwk.zbee_sec_src64).oui.registration().org
                            #                     if 'zbee_nwk' in packet 
                            #                     else None
                            #                     for packet in pcap],

                            'Manufacturer': []
                        }

        for packet in pcap:
            try:
                if 'zbee_nwk' in packet:
                    packets['Manufacturer'].append(EUI(packet.zbee_nwk.zbee_sec_src64).oui.registration().org)
                else:
                    packets['Manufacturer'].append(None)
            except:
                packets['Manufacturer'].append(None)
            
    except Exception as e:
        print("Error during reading packets! Skipping file...")
        print(e)
        pcap.close()
        return False

    return packets

# A function to print events or signature matches
def print_events(dfs: dict, conclusions: str):
    
    printed = False
    
    if conclusions != '':
        print("****Detected using periodic reporting signatures****")
        print(conclusions)
        printed = True

    for key, df in dfs.items():
        if type(df) == DataFrame:
            if key == 'Bulb':
                df.drop_duplicates(['Burst', key], keep='first', inplace=True)
                # df.drop_duplicates(['Group'], keep='first', inplace=True)
            else:
                df.drop_duplicates(['Burst'], keep='first', inplace=True)
            dfs[key] = df[df[key].notnull()].copy()

    if  (dfs['Sensor'] is not None and len(dfs['Sensor'])) or \
        (dfs['Lock'] is not None and len(dfs['Lock'])) or \
        (dfs['Bulb'] is not None and len(dfs['Bulb'])):
        print("****Detected using Command inference****")

    if type(dfs['Sensor']) == DataFrame:
        for k, row in enumerate(dfs['Sensor'].iterrows()):
            if row[-1]['Sensor'] and row[-1]['Sensor'] != 'Motion Sensor Rec':
                if row[-1]['Sensor'] == 'Motion Sensor':
                    action = 'detected motion'
                elif row[-1]['Sensor'] == 'Door Sensor':
                    action = 'opened/closed'
                elif row[-1]['Sensor'] == 'Flood Sensor':
                    action = 'detected water leakage'
                else:
                    action = 'detected audio'

                print(f"{hex(int(row[-1]['Device'], 16))}: {row[-1]['Manufacturer']} {row[-1]['Sensor']} {action} at {row[-1]['Time']}")
        printed = True

    if type(dfs['Lock']) == DataFrame:
        for k, row in enumerate(dfs['Lock'].iterrows()):
            if row[-1]['Lock']:
                print(f"{hex(int(row[-1]['Device'], 16))}: {row[-1]['Manufacturer']} lock locked/unlocked at {row[-1]['Time']}")
        printed = True

    if type(dfs['Bulb']) == DataFrame:

        for k, row in enumerate(dfs['Bulb'].iterrows()):            
            action = 'switched on/off ' if row[-1]['Bulb'] == 'Bulb|Plug' else ''

            if row[-1]['Bulb']:
                # print(f"{hex(int(row[-1]['Device'], 16))}: {row[-1]['Manufacturer']} {row[-1]['Bulb'].split('_')[0]} {action}at {row[-1]['Time']}")
                print(f"{hex(int(row[-1]['Device'], 16))}: {row[-1]['Manufacturer']} {row[-1]['Bulb']} {action}at {row[-1]['Time']}")
        printed = True

    if not printed:
        print("\nNo event detected from both modules!")

def start(pcapfile):

    print('Filename:', pcapfile)

    packets = extract_data(pcapfile)

    if not packets:
        return

    main_df = pd.DataFrame(packets)

    # Packet Analyser object is created to clean the data
    main_pa = PackerAnalyser(main_df)
    mapper = Mapper(main_df)

    # Using Mapper object to fetch all device types
    devices = mapper.fetch_device_types(pcapfile)
    addresses, man_dict = mapper.get_all_devices(pcapfile)

    # A dictionary is cleaned for proper display of device types
    network_address_df = pd.DataFrame(man_dict)
    network_address_df.index += 1

    network_address_df['Device Type'] = network_address_df['Address'].apply(lambda x: mapper.set_device(x))
    network_address_df['Address'] = network_address_df['Address'].apply(lambda x: hex(int(x, 16)))

    print('\n', network_address_df, end='\n\n')

    main_df = mapper.add_device_type_to_data()
    main_df = main_pa.process_data()        
    mapper.get_data_request_difference(main_df)

    # Complex logic I know :p but it is quick
    main_df['Manufacturer'] = main_df.apply(lambda x:   man_dict['Manufacturer'][man_dict['Address'].index(x['Source'])]
                                                        if x['Source'] in man_dict['Address']
                                                        else
                                                        man_dict['Manufacturer'][man_dict['Address'].index(x['Destination'])]
                                                        if x['Destination'] in man_dict['Address']
                                                        else None
                                                        , axis=1)

    if not os.path.exists("uncleaned"):
        os.mkdir("uncleaned")

    uncleaned_files_path = os.path.join(os.getcwd(), 'uncleaned')
    main_df.to_csv(os.path.join(uncleaned_files_path, f"uncleaned_{pcapfile.split('.')[0]}.csv"), index=False)

    for addr in broadcast_addresses:
        if addr in addresses:
            addresses.remove(addr)

    dfs =   {
                'Sensor': list(), 
                'Lock': list(), 
                'Bulb': list()
            }

    # Module 2 signature if matchese then conclusion is appended to conclusions string
    conclusions = ""

    for addr in addresses:
        
        #--------------- Module 1 ---------------#
        # If module 1 doesnt works then test on basis of module 2
        # Create Analyser object based on each address
        addr_df = main_df[(main_df['Source'] == addr) | (main_df['Destination'] == addr)].copy()
        pa = PackerAnalyser(addr_df)
        
        sensor_df = pa.detect_sensor()
        sensor_df = sensor_df[sensor_df['Sensor'].notnull()].copy()

        # If device is detected as sensor then move on to next device
        # Same goes for other detections too down below
        if len(sensor_df):
            sensor_df['Device'] = addr
            dfs['Sensor'].append(sensor_df)
            continue

        lock_df = pa.detect_locks()
        
        if len(lock_df):
            lock_df['Device'] = addr
            dfs['Lock'].append(lock_df)
            continue

        bulb_df = pa.detect_bulbs()

        if len(bulb_df):
            bulb_df['Device'] = addr
            dfs['Bulb'].append(bulb_df)
            continue

        #--------------- END ---------------#

        #--------------- Module 2 ---------------#

        # comparator = Comparator(addr_df.drop(['Discovery', 'Mac', 'Manufacturer'], axis = 1))
        comparator = Comparator(addr_df.drop(['Discovery', 'Manufacturer', 'DR_Avg_Time'], axis = 1))
        conclusions += comparator.start_comparator(addr)

        #--------------- END ---------------#

    # Stores final dataframe to print the final detections
    final_df =  {
                    'Sensor': None,
                    'Lock': None,
                    'Bulb': None
                }

    if not os.path.exists("cleaned"):
        os.mkdir("cleaned")

    cleaned_files_path = os.path.join(os.getcwd(), 'cleaned')

    for key, df in dfs.items():
        if df:
            final_df[key] = pd.concat(df) if len(df) else df[0]
            final_df[key].sort_values('Timestamp', ascending=True, inplace=True)
            final_df[key].to_csv(os.path.join(cleaned_files_path, f"{key}_{pcapfile.split('.')[0]}.csv"), index=False)

    print_events(final_df, conclusions)
    print()


# Program Start
def main():
    for pcapfile in glob.glob("*.pcapng") + glob.glob("*.pcap"):
        start(pcapfile)


if __name__ == '__main__':
    warnings.filterwarnings("ignore")
    broadcast_addresses = ['0x0000fffc', '0x0000fffd', '0x0000ffff']
    main()
