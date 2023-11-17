
import streamlit as st
import pandas as pd
import plotly.express as px
import numpy as np
import time

# Sample data generation
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

# Function to generate real-time data (smaller batches)
def generate_real_time_data():
    current_time = pd.Timestamp.now()
    categories = ['Malware', 'Phishing', 'DDoS', 'Insider Threat']
    severity_levels = ['High', 'Medium', 'Low']
    new_data = pd.DataFrame({
        'Date': [current_time],
        'Category': [np.random.choice(categories)],
        'Severity': [np.random.choice(severity_levels)]
    })
    return new_data

# Authentication
def authenticate_user(username, password):
    return username == "admin" and password == "password"  # Placeholder

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

# Function to convert DataFrame to CSV
def convert_df_to_csv(df):
    return df.to_csv(index=False).encode('utf-8')

# Sidebar for Login
with st.sidebar:
    with st.expander("Login", expanded=True):
        username = st.text_input("Username", key="login_username")
        password = st.text_input("Password", type="password", key="login_password")
        if authenticate_user(username, password):
            st.session_state['authenticated'] = True
            st.success("Logged in successfully!")
        else:
            st.session_state['authenticated'] = False

# Check if user is authenticated
if st.session_state.get('authenticated', False):
    # Additional Sidebar Content after Authentication
    with st.sidebar:
        with st.expander("Filters", expanded=True):
            selected_severity = st.multiselect('Select Severity Level', ['High', 'Medium', 'Low'], key="filter_severity")
            selected_category = st.multiselect('Select Threat Category', ['Malware', 'Phishing', 'DDoS', 'Insider Threat'], key="filter_category")

        with st.expander("Incident Reporting", expanded=False):
            with st.form(key="incident_reporting_form"):
                form_date = st.date_input("Date", key="form_date")
                form_category = st.selectbox("Category", ['Malware', 'Phishing', 'DDoS', 'Insider Threat'], key="form_category")
                form_severity = st.selectbox("Severity", ['High', 'Medium', 'Low'], key="form_severity")
                form_description = st.text_area("Description", key="form_description")
                submit_button = st.form_submit_button("Report Incident")

                # Add new incident to the DataFrame
                if submit_button:
                    new_incident = pd.DataFrame([[form_date, form_category, form_severity, form_description]],
                                                columns=['Date', 'Category', 'Severity', 'Description'])
                    st.session_state['incident_reports'] = pd.concat([st.session_state['incident_reports'], new_incident], ignore_index=True)

    st.title('Threat Intelligence Dashboard')

    # Row 1: Threat Level and Real-time Monitoring Chart
    row1_col1, row1_col2 = st.columns([2, 5])
    with row1_col1:
        data = generate_sample_data()
        threat_level, high_severity_count, total_count = calculate_threat_level(data)
        st.markdown(f"## Threat Level: {threat_level}")
        st.markdown(f"### Details: {high_severity_count} high severity threats out of {total_count} total threats.")

    with row1_col2:
        # Placeholder for the chart
        chart_placeholder = st.empty()

    # Simulating real-time data update
    with st.empty():
        while True:
            new_data = generate_real_time_data()
            data = pd.concat([data, new_data], ignore_index=True)
            fig = px.histogram(data, x='Date', y='Category', color='Severity', barmode='group')
            chart_placeholder.plotly_chart(fig, use_container_width=True)
            time.sleep(1)  # Adjust the sleep time as needed

    # Row 2: Data Table and Incident Reports
    row2_col1, row2_col2 = st.columns([2, 5])
    with row2_col1:
        st.write("Real-time Threat Monitoring")
        st.dataframe(data)

    with row2_col2:
        st.write("Incident Reports")
        st.dataframe(st.session_state['incident_reports'])

    # Download Button
    st.download_button(
        label="Download data as CSV",
        data=convert_df_to_csv(data),
        file_name='threat_data.csv',
        mime='text/csv',
    )

    st.write("SecureAI Threat Intelligence Dashboard")
else:
    st.info("Please log in to access the dashboard.")


















