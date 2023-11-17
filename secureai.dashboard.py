
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

# Function to convert DataFrame to CSV for download
def convert_df_to_csv(df):
    return df.to_csv(index=False).encode('utf-8')

# Sidebar with login
with st.sidebar:
    # Login Section
    with st.expander("Login", expanded=True):
        username = st.text_input("Username", key="login_username")
        password = st.text_input("Password", type="password", key="login_password")
        if authenticate_user(username, password):
            st.session_state['authenticated'] = True
            st.success("Logged in successfully!")
        else:
            st.session_state['authenticated'] = False

if st.session_state.get('authenticated', False):
    st.title('Threat Intelligence Dashboard')

    # Adjusted Main dashboard layout with a more balanced arrangement
    # Row 1: Threat Level and Real-time Monitoring Chart
    row1_col1, row1_col2 = st.columns([2, 5])  # Adjusted column widths for a more balanced layout
    with row1_col1:
        # Threat Level Display
        data = generate_sample_data()
        threat_level, high_severity_count, total_count = calculate_threat_level(data)
        st.markdown(f"## Threat Level: {threat_level}")
        st.markdown(f"### Details: {high_severity_count} high severity threats out of {total_count} total threats.")

    with row1_col2:
        # Real-time Monitoring Chart
        fig = px.histogram(data, x='Date', y='Category', color='Severity', barmode='group')
        st.plotly_chart(fig)

    # Row 2: Data Table and Incident Reports
    row2_col1, row2_col2 = st.columns([2, 5])  # Keeping the same ratio as above
    with row2_col1:
        st.write("Real-time Threat Monitoring")
        st.dataframe(data)

    with row2_col2:
        st.write("Incident Reports")
        st.dataframe(st.session_state['incident_reports'])

    # Row 3: Download Data Button
    st.download_button(
        label="Download data as CSV",
        data=convert_df_to_csv(data),
        file_name='threat_data.csv',
        mime='text/csv',
    )

    # Footer
    st.write("SecureAI Threat Intelligence Dashboard")
else:
    st.info("Please log in to access the dashboard.")








