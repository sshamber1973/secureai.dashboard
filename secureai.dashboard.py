
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

# Sidebar with filters, incident reporting form, and login
with st.sidebar:
    # Login Section
    with st.expander("Login", expanded=True):
        username = st.text_input("Username", key="login_username")
        password = st.text_input("Password", type="password", key="login_password")
        if authenticate_user(username, password):
            st.success("Logged in successfully!")
        else:
            st.error("Please enter valid credentials")

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

# Main dashboard layout
st.title('Threat Intelligence Dashboard')

# Top Section: Threat Level Indicator and Real-time Monitoring Chart
col1, col2 = st.columns(2)
with col1:
    # Threat Level Display
    data = generate_sample_data()
    threat_level, high_severity_count, total_count = calculate_threat_level(data)
    st.markdown(f"## Threat Level: {threat_level}")
    st.markdown(f"### Details: {high_severity_count} high severity threats out of {total_count} total threats.")

with col2:
    # Real-time Monitoring Chart
    fig = px.histogram(data, x='Date', y='Category', color='Severity', barmode='group')
    st.plotly_chart(fig)

# Middle Section: Data Table and Incident Reports
col3, col4 = st.columns(2)
with col3:
    st.write("Real-time Threat Monitoring")
    st.dataframe(data)

with col4:
    st.write("Incident Reports")
    st.dataframe(st.session_state['incident_reports'])

# Bottom Section: Download Data
st.download_button(
    label="Download data as CSV",
    data=convert_df_to_csv(data),
    file_name='threat_data.csv',
    mime='text/csv',
)

# Footer
st.write("SecureAI Threat Intelligence Dashboard")



