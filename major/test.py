import streamlit as st
import pandas as pd
import numpy as np
import pickle
import boto3
import base64
from sklearn.preprocessing import StandardScaler
from streamlit_option_menu import option_menu

# Initialize the SNS client (ensure AWS CLI is configured with appropriate permissions)
sns_client = boto3.client('sns', region_name='eu-north-1')  # Replace 'eu-north-1' with your region
sns_topic_arn = 'arn:aws:sns:eu-north-1:711387115919:AnomalyDetectionAlertsNew'  # Replace with your SNS Topic ARN

# Convert the background image to base64
def get_base64_image(image_path):
    with open(image_path, "rb") as img_file:
        return base64.b64encode(img_file.read()).decode()

# Load the background image and convert it to base64
image_path = "/home/rgukt/Downloads/pro.jpg"  # Path to your high-definition background image
base64_image = get_base64_image(image_path)

# Set background and topbar colors
background_color = "#2E3B4E"  # Example background color for the topbar
text_color = "#FFFFFF"  # Example white text color for the topbar

# Apply CSS with the background image and topbar styling
background_css = f"""
<style>
.stApp {{
    background-image: url("data:image/jpeg;base64,{base64_image}");
    background-size: cover;
    background-position: center;
    background-attachment: fixed;
}}
.streamlit-topbar {{
    background-color: {background_color};
    color: {text_color};
    font-size: 20px;
    font-weight: bold;
}}
.stTitle, .stSidebar {{
    color: white;
    background-color: rgba(0, 0, 0, 0.6);
}}
</style>
"""
st.markdown(background_css, unsafe_allow_html=True)

# Load trained model and scaler
model = pickle.load(open("model.pkl", "rb"))
scaler = StandardScaler()
scaler.fit(pd.DataFrame(np.random.randn(100, 10)))  # Placeholder to fit scaler

# Main function to handle Streamlit UI and logic
def main():
    st.title("Network Anomaly Detection System")
    menu = ["Home", "Anomaly Detection","Visualizations", "About"]
    
    # Create the menu in the sidebar
    with st.sidebar:
        choice = option_menu("Menu", menu, icons=['house', 'alarm-fill', 'info-circle'], menu_icon="cast", default_index=0)

    if choice == "Home":
        st.markdown("<div class='home-text'><h4>Welcome To The Network Anomaly Detection Alerting System Through     AWS SNS</h4></div>", unsafe_allow_html=True)

    elif choice == "Anomaly Detection":
        st.subheader("Anomaly Detection with Random Forest")
        st.header("Enter Feature Values")

        # Define mappings for protocol_type, service names, and flag descriptions
        protocol_mapping = {"tcp": 0, "udp": 1, "icmp": 2}
        service_mapping = {
            "ftp": 0, "http": 1, "smtp": 2, "dns": 3, "telnet": 4,
            "ftp_data": 5, "ldap": 6, "pop3": 7, "irc": 8, "ntp": 9
        }
        flag_mapping = {
            "SF": 0, "S0": 1, "REJ": 2, "RSTO": 3, "RSTOS0": 4,
            "RSTR": 5, "SH": 6, "S1": 7, "S2": 8, "S3": 9
        }

        # Collect user inputs for each feature
        protocol_type = st.selectbox("Protocol Type", list(protocol_mapping.keys()))
        service = st.selectbox("Service", list(service_mapping.keys()))
        flag = st.selectbox("Flag", list(flag_mapping.keys()))
        src_bytes = st.number_input("Source Bytes", min_value=0, max_value=int(1e7), value=0, step=1)
        dst_bytes = st.number_input("Destination Bytes", min_value=0, max_value=int(1e7), value=0, step=1)
        count = st.number_input("Count", min_value=0, max_value=255, value=0, step=1)
        same_srv_rate = st.number_input("Same Service Rate", min_value=0.0, max_value=1.0, value=0.0, step=0.01)
        diff_srv_rate = st.number_input("Different Service Rate", min_value=0.0, max_value=1.0, value=0.0, step=0.01)
        dst_host_srv_count = st.number_input("Destination Host Service Count", min_value=0, max_value=255, value=0, step=1)
        dst_host_same_srv_rate = st.number_input("Destination Host Same Service Rate", min_value=0.0, max_value=1.0, value=0.0, step=0.01)

        # Convert user selections to encoded values
        protocol_type_encoded = protocol_mapping[protocol_type]
        service_encoded = service_mapping[service]
        flag_encoded = flag_mapping[flag]

        # Prepare input for model prediction
        input_data = np.array([
            protocol_type_encoded, service_encoded, flag_encoded, src_bytes, dst_bytes, count,
            same_srv_rate, diff_srv_rate, dst_host_srv_count, dst_host_same_srv_rate
        ]).reshape(1, -1)

        # Scale input data
        scaled_data = scaler.transform(input_data)
         # Predict and display results
        if st.button("Predict Anomaly"):
            prediction = model.predict(scaled_data)
            if prediction[0] == 1:
                st.write("Prediction: ANOMALY IS NOT DETECTED")
            else:
                st.write("Prediction: ANOMALY IS DETECTED")
                
                # Send an SNS alert if an anomaly is detected
                message = f"Anomaly detected in the network traffic:\nProtocol: {protocol_type}, Service: {service}, Flag: {flag}"
                sns_client.publish(
                    TopicArn=sns_topic_arn,
                    Message=message,
                    Subject="Anomaly Detection Alert"
                )
                st.success("Anomaly detected. Alert sent to your email!")
    elif choice == "Visualizations":
        st.subheader("Anomaly Visualizations")

        # Simulate some data for visualization (replace with real data if available)
        np.random.seed(42)
        data_size = 200
        df_vis = pd.DataFrame({
            "protocol_type": np.random.choice(["tcp", "udp", "icmp"], data_size),
            "src_bytes": np.random.randint(0, 10000, data_size),
            "dst_bytes": np.random.randint(0, 10000, data_size),
            "anomaly": np.random.choice([0, 1], data_size, p=[0.8, 0.2])
        })

        st.markdown("### 📊 Anomaly Distribution (Bar Chart)")
        anomaly_counts = df_vis['anomaly'].value_counts().rename(index={0: "Anomaly", 1: "Normal"})
        st.bar_chart(anomaly_counts)

        st.markdown("### 📉 Source Bytes vs Destination Bytes (Scatter Plot)")
        st.write("Red = Anomaly, Blue = Normal")

        scatter_df = df_vis.copy()
        scatter_df['color'] = scatter_df['anomaly'].map({0: 'red', 1: 'blue'})
        st.plotly_chart(
            {
                "data": [
                    {
                        "x": scatter_df['src_bytes'],
                        "y": scatter_df['dst_bytes'],
                        "mode": "markers",
                        "marker": {"color": scatter_df['color']},
                        "type": "scatter",
                        "name": "Anomaly Scatter"
                    }
                ],
                "layout": {
                    "xaxis": {"title": "Source Bytes"},
                    "yaxis": {"title": "Destination Bytes"},
                    "height": 500,
                }
            }
        )

        st.markdown("### 🔍 Protocol Usage")
        st.bar_chart(df_vis["protocol_type"].value_counts())
    elif choice == "About":
        st.subheader("About")
        st.write("""
            The Network Anomaly Detection Alerting System uses machine learning to detect unusual network traffic and triggers alerts via AWS SNS. It ensures that the real-time notifications through email or SMS, providing proactive security alerts. The system integrates with AWS for seamless, automated operation.
        """)

if __name__ == "__main__":
    main()

