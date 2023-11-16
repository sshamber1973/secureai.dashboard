
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

# In-memory storage for incident reports
if 'incident_reports' not in st.session_state:
    st.session_state['incident_reports'] = pd.DataFrame(columns=['Date', 'Category', 'Severity', 'Description'])

# Authentication (placeholder, implement real authentication for production)
def authenticate_user(username, password):
    return username == "admin" and password == "password"  # Replace with real authentication

# Login Page
username = st.sidebar.text_input("Username")
password = st.sidebar.text_input("Password", type="password")
if not authenticate_user(username, password):
    st.error("Please enter valid credentials")
    st.stop()

st.title('Threat Intelligence Dashboard')

# Sidebar filters
st.sidebar.title("Filters")
selected_severity = st.sidebar.multiselect('Select Severity Level', ['High', 'Medium', 'Low'])
selected_category = st.sidebar.multiselect('Select Threat Category', ['Malware', 'Phishing', 'DDoS', 'Insider Threat'])

# Incident Reporting Form
st.sidebar.title("Incident Reporting")
with st.sidebar.form("incident_form"):
    form_date = st.date_input("Date")
    form_category = st.selectbox("Category", ['Malware', 'Phishing', 'DDoS', 'Insider Threat'])
    form_severity = st.selectbox("Severity", ['High', 'Medium', 'Low'])
    form_description = st.text_area("Description")
    submit_button = st.form_submit_button("Report Incident")

    # Add new incident to the DataFrame
    if submit_button:
        new_incident = pd.DataFrame([[form_date, form_category, form_severity, form_description]],
                                    columns=['Date', 'Category', 'Severity', 'Description'])
        st.session_state['incident_reports'] = pd.concat([st.session_state['incident_reports'], new_incident], ignore_index=True)

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

