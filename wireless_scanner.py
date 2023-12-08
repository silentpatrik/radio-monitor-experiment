import time
from rtlsdr import RtlSdr
import os
import subprocess
import logging
import numpy as np
import time
from scapy.all import sniff, Dot11
import bluetooth
from scapy.all import IFACES

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def scan_bluetooth_devices():
    nearby_devices = bluetooth.discover_devices(duration=8, lookup_names=True, flush_cache=True)
    for addr, name in nearby_devices:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        logging.info(f"Type: Bluetooth, Device Name: {name}, Hardware Address: {addr}, Timestamp: {timestamp}")

def scan_bluetooth_devices2(sdr):
    try:
        # Configure the HackRF device for Bluetooth frequencies
        sdr.sample_rate = 2.048e6  # Hz
        sdr.center_freq = 2.402e9  # Hz (Bluetooth frequency)
        sdr.freq_correction = 60   # PPM
        sdr.gain = 'auto'

        nearby_devices = bluetooth.discover_devices(duration=8, lookup_names=True, flush_cache=True, device_id=sdr.device_index)

        for addr, name in nearby_devices:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            logging.info(f"Type: Bluetooth, Device Name: {name}, Hardware Address: {addr}, Timestamp: {timestamp}")
    except Exception as e:
        logging.error(f"Bluetooth scanning error: {e}")


def scan_wifi_networks(interface):
    def process_packet(packet):
        if packet.haslayer(Dot11):
            try:
                if packet.type == 0 and packet.subtype == 4:  # Probe Request
                    mac_address = packet.addr2
                    rssi = packet.dBm_AntSignal
                    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                    logging.info(f"Type: Wi-Fi, MAC Address: {mac_address}, RSSI: {rssi}, Timestamp: {timestamp}")
            except Exception as e:
                logging.error(f"Wi-Fi scanning error: {e}")

    sniff(iface=interface, prn=process_packet, count=100, timeout=30)

def perform_rf_scan(start_freq, end_freq, step_size):
    sdr = RtlSdr()
    start_time = time.time()

    try:
        for freq in range(start_freq, end_freq, step_size):
            # Check for timeout
            if time.time() - start_time > 30:
                logging.info("RF scan timed out after 30 seconds.")
                break

            sdr.center_freq = freq
            sdr.sample_rate = 2.048e6
            sdr.gain = 'auto'
            
            # Provide feedback every 3 seconds
            if int(time.time() - start_time) % 3 == 0:
                logging.info(f"Scanning frequency: {freq} Hz")

            raw_data = sdr.read_samples(256*1024)
            signal_strength = calculate_signal_strength(raw_data)
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            logging.info(f"Frequency: {freq} Hz, Signal Strength: {signal_strength} dB, Timestamp: {timestamp}")

            # Sleep for a short duration to avoid flooding the log
            time.sleep(0.1)

    except Exception as e:
        logging.error(f"RF scanning error: {e}")
    finally:
        sdr.close()

def calculate_signal_strength(samples):
    power = np.mean(np.abs(samples)**2)
    return 10 * np.log10(power)


def get_wireless_interfaces():
    try:
        iwconfig_output = subprocess.check_output('iwconfig', stderr=subprocess.STDOUT).decode('utf-8')
        wireless_interfaces = [line.split()[0] for line in iwconfig_output.split('\n') if 'IEEE 802.11' in line]
        return wireless_interfaces
    except subprocess.CalledProcessError as e:
        logging.error("Failed to get wireless interfaces")
        return []
def list_sdr_devices():
    for i in range(5):  # Check the first 5 indices
        try:
            sdr = RtlSdr(device_index=i)
            print(f"Found SDR device at index {i}")
            sdr.close()
        except Exception    as e:
            pass

def choose_sdr_device():
    d=list_sdr_devices()
    print(d)
    if d == None:
        return 0
    choice = input("Enter the index of the SDR device you want to use: ")
    return int(choice)

# In your main function

def choose_wireless_interface():
    interfaces = get_wireless_interfaces()
    if len(interfaces) == 0:
        logging.error("No wireless interfaces found.")
        return None
    # elif len(interfaces) == 1:
    #     return interfaces[0]
    else:
        print("Multiple wireless interfaces found. Please choose one:")
        for i, iface in enumerate(interfaces):
            print(f"{i + 1}: {iface}")
        choice = int(input("Enter the number of the interface you want to use: "))
        return interfaces[choice - 1]

def check_hackrf_presence():
    try:
        sdr = RtlSdr()
        sdr.close()
        return True
    except Exception as e:
        logging.error(f"HackRF device not found: {e.message}")
        return False
     
def scan_wireless_network_interfaces2()
    if not check_hackrf_presence():
        logging.error("Error: HackRF device not found. Please connect a HackRF device.")
        
        return
    
def scan_wireless_network_interfaces2():
    try:
        for iface in IFACES.dev_from_index:
            name = IFACES.dev_from_index[iface].name
            hw_addr = IFACES.dev_from_index[iface].mac
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            logging.info(f"Type: Wireless, Interface Name: {name}, Hardware Address: {hw_addr}, Timestamp: {timestamp}")
    except Exception as e:
        logging.error(f"Wireless network interface scanning error: {e}")

def main():
    sdr_device_index = choose_sdr_device()
    if(sdr_device_index == None):
        logging.error("No SDR device found. Please connect a SDR device.")

    logging.info("Starting interface scanning...")
    wifi_interface = choose_wireless_interface()
    if wifi_interface:
        logging.info("Scanning Wi-Fi networks...")
        scan_wifi_networks(wifi_interface)

    logging.info("Scanning Bluetooth devices...")
    scan_bluetooth_devices()
    logging.info("Scanning RF spectrum...")
    perform_rf_scan(0, 6e9, 1e6)  # Scanning from 0 to 6 GHz with 1 MHz steps

if __name__ == "__main__":
    main()
