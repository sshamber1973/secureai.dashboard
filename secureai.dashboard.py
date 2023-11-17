
import streamlit as st
import pandas as pd
import plotly.express as px
import numpy as np

# Sample data generation (Replace with real threat data in actual implementation)
def generate_sample_data():
    dates = pd.date_range(start='2023-01-01', end='2023-01-31', freq='H')
    categories = ['Malware', 'Phishing', 'DDoS', 'Insider Threat']
    severity_levels = ['High', 'Medium', 'Low']

    data = pd.DataFrame({
        'Date': np.random.choice(dates, size=100),
        'Category': np.random.choice(categories, size=100),
        'Severity': np.random.choice(severity_levels, size=100)
    })
    return data

# Authentication (placeholder, implement real authentication for production)
def authenticate_user(username, password):
    return username == "admin" and password == "password"  # Replace with real authentication

# In-memory storage for incident reports
if 'incident_reports' not in st.session_state:
    st.session_state['incident_reports'] = pd.DataFrame(columns=['Date', 'Category', 'Severity', 'Description'])

# Calculate threat level
def calculate_threat_level(data):
    high_severity_count = len(data[data['Severity'] == 'High'])
    total_count = len(data)
    if total_count == 0:
        return 'Green', 0, total_count  # No threats detected

    high_severity_proportion = high_severity_count / total_count
    if high_severity_proportion > 0.5:
        return 'Red', high_severity_count, total_count
    elif high_severity_proportion > 0.2:
        return 'Orange', high_severity_count, total_count
    else:
        return 'Yellow', high_severity_count, total_count

# Sidebar Layout for Login and Filters
with st.sidebar:
    st.title("Control Panel")
    
    # Login Section
    with st.expander("Login", expanded=True):
        username = st.text_input("Username", key="login_username")
        password = st.text_input("Password", type="password", key="login_password")
        if st.button("Login"):
            if not authenticate_user(username, password):
                st.error("Please enter valid credentials")
                st.stop()
    
    # Filters Section
    with st.expander("Filters", expanded=True):
        selected_severity = st.multiselect('Select Severity Level', ['High', 'Medium', 'Low'], key="filter_severity")
        selected_category = st.multiselect('Select Threat Category', ['Malware', 'Phishing', 'DDoS', 'Insider Threat'], key="filter_category")

    # Incident Reporting Section
    with st.expander("Incident Reporting", expanded=False):
        with st.form(key="incident_reporting_form"):
            form_date = st.date_input("Date", key="form_date")
            form_category = st.selectbox("Category", ['Malware', 'Phishing', 'DDoS', 'Insider Threat'], key="form_category")
            form_severity = st.selectbox("Severity", ['High', 'Medium', 'Low'], key="form_severity")
            form_description = st.text_area("Description", key="form_description")
            submit_button = st.form_submit_button("Report Incident")

# Main Content
st.title('Threat Intelligence Dashboard')

# Display the real-time threat level indicator
data = generate_sample_data()
threat_level, high_severity_count, total_count = calculate_threat_level(data)
st.markdown(f"## Threat Level: {threat_level}")
st.markdown(f"### Details: {high_severity_count} high severity threats out of {total_count} total threats.")

# Load and filter data
data = generate_sample_data()
if selected_severity:
    data = data[data['Severity'].isin(selected_severity)]
if selected_category:
    data = data[data['Category'].isin(selected_category)]

# Display data
st.write("Real-time Threat Monitoring")
st.dataframe(data)

# Interactive Chart
st.write("Threat Analysis")
fig = px.histogram(data, x='Date', y='Category', color='Severity', barmode='group')
st.plotly_chart(fig)

# Download data (sample implementation)
@st.cache_data
def convert_df_to_csv(df):
    return df.to_csv(index=False).encode('utf-8')

csv = convert_df_to_csv(data)
st.download_button(
    label="Download data as CSV",
    data=csv,
    file_name='threat_data.csv',
    mime='text/csv',
)

# Display Incident Reports
st.write("Incident Reports")
st.dataframe(st.session_state['incident_reports'])

# Footer
st.write("SecureAI Threat Intelligence Dashboard")


