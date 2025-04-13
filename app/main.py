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
            st.success("Port scan complete.")
            st.dataframe(port_df)

with tab4:
    st.header("🌐 VirusTotal URL Scan")
    user_url = st.text_input("Enter URL to scan")
    if st.button("Scan URL"):
        if user_url:
            result = urlReport(user_url)
            if result:
                st.success("URL scan complete.")
                st.write(result)
        else:
            st.warning("Please enter a valid URL.")
