import streamlit as st
from utils import getNetworkDevices, capture_packets, portscanner, urlReport
import pandas as pd

st.set_page_config(page_title="NetSec Toolkit", layout="wide")
st.title("🔐 Network Security Toolkit")

tab1, tab2, tab3, tab4 = st.tabs(["Network Devices", "Packet Capture", "Port Scan", "VirusTotal Scan"])

with tab1:
    st.header("🔍 Scan Network Devices")
    if st.button("Scan Devices (Bettercap)"):
        with st.spinner("Scanning..."):
            devices = getNetworkDevices()
            if devices:
                st.success("Scan complete!")
                st.dataframe(pd.DataFrame(devices))
            else:
                st.warning("No devices found or scan failed.")

with tab2:
    st.header("📡 Capture Network Packets")
    if st.button("Start Packet Capture"):
        with st.spinner("Capturing packets..."):
            df_packets = capture_packets()
            st.success(f"Captured {len(df_packets)} packets.")
            st.dataframe(df_packets)
with tab3:
    st.header("🛡 Port Scanner (Localhost)")
    if st.button("Run Port Scan"):
        with st.spinner("Scanning ports..."):
            port_df = portscanner()

            # Flatten the 'portInfo' dictionary into columns
            if not port_df.empty:
                flat_rows = []
                for _, row in port_df.iterrows():
                    flat = {
                        'Port': row['port'],
                        'Protocol': row['tcpProtocol'],
                        'State': row['portState'],
                    }
                    # Add individual fields from 'portInfo'
                    for key, value in row['portInfo'].items():
                        flat[key] = value
                    flat_rows.append(flat)

                formatted_df = pd.DataFrame(flat_rows)
                st.success("Port scan complete.")
                st.dataframe(formatted_df)
            else:
                st.warning("No ports found or scanning failed.")

with tab4:
    st.header("🌐 VirusTotal URL Scan")
    user_url = st.text_input("Enter URL to scan")

    if st.button("Scan URL"):
        if user_url:
            result = urlReport(user_url)
            if result and isinstance(result, dict):
                st.success("URL scan complete.")
                
                # Flatten and format the result into a readable table
                flat_data = []
                for key, value in result.items():
                    if isinstance(value, dict):
                        for subkey, subvalue in value.items():
                            flat_data.append({"Field": f"{key}.{subkey}", "Value": subvalue})
                    else:
                        flat_data.append({"Field": key, "Value": value})

                df = pd.DataFrame(flat_data)
                st.dataframe(df)
            else:
                st.warning("Failed to parse response from VirusTotal.")
        else:
            st.warning("Please enter a valid URL.")
