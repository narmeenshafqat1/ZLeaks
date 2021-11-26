# ZLeaks
ZLeaks identifies Zigbee devices in the target Zigbee network and user-triggered events based on the following two approaches.

Approach 1: Command Inference
This identifies devices (sensors, locks, bulbs and plugs) and associated events from the encrypted Zigbee traffic by inferring the functionality specific APL command present in the event burst.

Approach 2: Periodic Reporting Correlation
It makes use of the device's periodic reporting signatures, i.e. signatures collected when the device is in the idle state. The comparator module correlates the signatures of device in real traffic with existing signatures to identify known devices in the encrypted traffic.

Details regarding the underlying approaches are available at https://arxiv.org/abs/2107.10830

Usage: To run the tool, simply place the test capture in zleaks folder and run the packet analyzer
==> python packet_analyzer.py

(Optional) In order to identify any known device, it is required to first extract the device signatures. Place the wireshark capture in the zleaks folder and run the extractor.
==> python signature_extractor.py

The address mapper file determines the logical device type of the target device and binds it with Network address, MAC address and Manufacturer identifier, that aids in device analysis.

Note: You might need to import pandas, numpy and pyshark if not already installed.
