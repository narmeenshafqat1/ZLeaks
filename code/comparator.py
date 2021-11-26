from signature_extractor import SignatureExtractor
from address_mapper import Mapper

import pandas as pd
import glob
import os


class Comparator():

    def __init__(self, df, thresh_packets=2, thresh_percent=0.05):
        self.df = df
        self.thresh_packets = thresh_packets
        self.thresh_percent = thresh_percent

    #--------------- Helper functions ---------------#

    # Returns a boolean after checking if two groups match
    # also checks if two groups match but there is a slight difference in order
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

    # Fetches all signatures in cwd
    def load_signatures(self):

        self.signatures = dict()

        if not os.path.exists("signatures"):
            return

        os.chdir(os.path.join(os.getcwd(), "signatures"))

        for folder in glob.glob('*_signatures'):
            path = os.path.join(folder, "*.csv")
            dfs = [pd.read_csv(csvfile) for csvfile in glob.glob(path)]
            if dfs:
                folder_name = ''.join(folder.split('_')[:-1])
                self.signatures[folder_name] = {}
                self.signatures[folder_name]['signatures'] = sorted(dfs, key=lambda df: df['Gap'].iloc[0], reverse=False)
                self.signatures[folder_name]['checked'] = [False] * len(self.signatures[folder_name]['signatures'])
                self.signatures[folder_name]['folder_check'] = False

        self.found_sig_dfs = {k: [] for k in self.signatures}
    
        os.chdir('..')

    # Loaded signatures are compared with the signature of the current file (or device data)
    def compare_signatures(self):

        gap_diff = 14

        for f in self.signatures:
            for k, sig in enumerate(self.signatures[f]['signatures']):
                for new_sig in self.new_signatures['signatures']:
                    
                    if  len(new_sig) == len(sig) and \
                        sig['Gap'].iloc[0] >= (new_sig['Gap'].iloc[0] - gap_diff) and \
                        sig['Gap'].iloc[0] <= (new_sig['Gap'].iloc[0] + gap_diff):
                        sorted_group1 = sig[self.cols].sort_values(['Payload_length'], ignore_index=True)
                        sorted_group2 = new_sig[self.cols].sort_values(['Payload_length'], ignore_index=True)

                        if self.compare_groups(sig, new_sig, sorted_group1, sorted_group2):
                            self.signatures[f]['checked'][k] = True

    # Returns a string with final conclusion that whether there is a match in signature or not
    def return_conclusion(self, device_name):

        max_sigs = 0

        # If greater than 50minutes then use AND or use OR
        for f in self.signatures:
            for k, s in enumerate(self.signatures[f]['signatures']):
                if s['Gap'].iloc[0] < 31 * 60 and not self.signatures[f]['checked'][k]: # and
                    break
                elif s['Gap'].iloc[0] >= 31 * 60 and self.signatures[f]['checked'][k]: # or
                    self.signatures[f]['folder_check'] = True
                elif k == len(self.signatures[f]['signatures']) - 1 and any(self.signatures[f]['checked']):
                    self.signatures[f]['folder_check'] = True

            if sum(self.signatures[f]['checked']) > max_sigs and self.signatures[f]['folder_check']:
                max_sigs = sum(self.signatures[f]['checked'])

        select_sigs = [f for f in self.signatures if self.signatures[f]['folder_check'] and sum(self.signatures[f]['checked']) == max_sigs]
        probable_sigs = [f for f in self.signatures if not self.signatures[f]['folder_check'] and sum(self.signatures[f]['checked'])]

        select = select_sigs if len(select_sigs) else probable_sigs

        final_conclusion =  f"{hex(int(device_name, 16))}: signature correlated with " \
                            if len(select_sigs) \
                            else \
                            f"{hex(int(device_name, 16))}: signature probably correlated with " \
                            if len(probable_sigs) \
                            else \
                            ""

        for k, sig in enumerate(select):
            if k == len(select) - 1:
                final_conclusion += f"{sig}\n"
            elif k == len(select) - 2:
                final_conclusion += f"{sig} and "
            else:
                final_conclusion += f"{sig}, "

        # Compares for similar mac id in signatures
        device_mac_id = self.df[(self.df['Source'].str.contains(device_name))]['Mac'].iloc[0]

        if device_mac_id:
            device_mac_id = ':'.join(device_mac_id.split(':')[:3])

            if len(select) > 1:
                matched_mac_id = []
                for sig in select:
                    temp_df = pd.concat(self.signatures[sig]['signatures'])
                    sig_mac_id = temp_df[~(temp_df['Src_device'].str.contains('ZC'))]['Mac'].iloc[0]
                    
                    if sig_mac_id:
                        sig_mac_id = ':'.join(sig_mac_id.split(':')[:3])
                    else:
                        continue
                    
                    if device_mac_id == sig_mac_id:
                        matched_mac_id.append(sig)

                if len(matched_mac_id) and (len(matched_mac_id) != len(select)):
                    final_conclusion += "Most correlated with "

                    for k, sig in enumerate(matched_mac_id):
                        if k == len(matched_mac_id) - 1:
                            final_conclusion += f"{sig}\n"
                        elif k == len(matched_mac_id) - 2:
                            final_conclusion += f"{sig} and "
                        else:
                            final_conclusion += f"{sig}, "

        return final_conclusion

    # Starts the comparator
    def start_comparator(self, device_name):
        
        self.load_signatures()

        self.sig_df = self.df.copy()

        # Generate signatures for the file to 
        # compare it with existing signatures
        extractor = SignatureExtractor(self.sig_df)
        mapper = Mapper(self.sig_df)

        # self.sig_df = extractor.process_data()
        self.new_signatures = extractor.start_extractor(mapper, self.sig_df)

        # Select columns for checking
        remove_columns = [  'Time', 'Timestamp', 'Sequence_number', 
                            'Source', 'Destination', 'Burst', 
                            'Packet_length', 'Mac']
        self.cols = [col for col in self.sig_df.columns if col not in remove_columns]
        #print(self.cols)
        self.compare_signatures()

        return self.return_conclusion(device_name)
