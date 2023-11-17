
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

    # Sidebar with filters and incident reporting form
    with st.sidebar:
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

                # Add new incident to the DataFrame
                if submit_button:
                    new_incident = pd.DataFrame([[form_date, form_category, form_severity, form_description]],
                                                columns=['Date', 'Category', 'Severity', 'Description'])
                    st.session_state['incident_reports'] = pd.concat([st.session_state['incident_reports'], new_incident], ignore_index=True)

    # Main dashboard layout
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
else:
    st.info("Please log in to access the dashboard.")




