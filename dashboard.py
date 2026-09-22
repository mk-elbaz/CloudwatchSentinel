import streamlit as st
from dotenv import load_dotenv
import os
import base64
from pathlib import Path

# Load environment variables from .env file
load_dotenv()

from src.aws_logs import CloudWatchCollector
from src.analyzer import LogAnalyzer
from src.database import Database
from src.models import AnalysisRun
from src.cloudfront_analytics import CloudFrontAnalytics
from src.cost_analyzer import AWSCostAnalyzer
from src.security_analyzer import AWSSecurityAnalyzer
from src.performance_analyzer import AWSPerformanceAnalyzer
from src.health_dashboard import AWSHealthDashboard
from src.compliance_checker import AWSComplianceChecker
from src.quota_monitor import AWSQuotaMonitor
from src.backup_analyzer import AWSBackupAnalyzer
from datetime import datetime, timedelta

# Page config
st.set_page_config(
    page_title="CloudWatch AI Sentinel",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize theme in session state
if 'theme' not in st.session_state:
    st.session_state['theme'] = 'dark'  # Default to dark mode

# Theme-aware CSS with full Streamlit overrides
def get_theme_css(theme):
    if theme == 'dark':
        return """
        <style>
            /* Dark theme - ensure all text is readable */
            .stApp {
                background-color: #0e1117;
                color: #fafafa;
            }
            [data-testid="stSidebar"] {
                background-color: #1e2130;
            }
            [data-testid="stSidebar"] * {
                color: #fafafa !important;
            }
            [data-testid="stHeader"] {
                background-color: #0e1117;
            }
            
            /* All text elements */
            .stApp p, .stApp span, .stApp label, .stApp div {
                color: #fafafa;
            }
            
            /* Headers */
            .stApp h1, .stApp h2, .stApp h3, .stApp h4, .stApp h5, .stApp h6 {
                color: #fafafa !important;
            }
            
            /* Markdown */
            [data-testid="stMarkdownContainer"] {
                color: #fafafa !important;
            }
            [data-testid="stMarkdownContainer"] p {
                color: #fafafa !important;
            }
            
            /* Metrics */
            [data-testid="stMetricValue"] {
                color: #fafafa !important;
            }
            [data-testid="stMetricLabel"] {
                color: #aaa !important;
            }
            
            /* Captions */
            .stCaption, small, [data-testid="stCaptionContainer"] {
                color: #888 !important;
            }
            
            /* Inputs and selects */
            [data-testid="stSelectbox"] label,
            [data-testid="stTextInput"] label,
            [data-testid="stNumberInput"] label,
            [data-testid="stSlider"] label {
                color: #fafafa !important;
            }
            
            /* Theme toggle button - dark background */
            [data-testid="stSidebar"] button {
                background-color: #2a2d3e !important;
                color: #fafafa !important;
                border: 1px solid #444 !important;
            }
            [data-testid="stSidebar"] button:hover {
                background-color: #3a3d4e !important;
                border-color: #2F3AE4 !important;
            }
            
            /* Regular buttons in dark mode */
            .stButton > button {
                background-color: #2F3AE4 !important;
                color: #ffffff !important;
                border: none !important;
                font-weight: 500 !important;
            }
            .stButton > button:hover {
                background-color: #2535b3 !important;
                box-shadow: 0 2px 8px rgba(47, 58, 228, 0.3) !important;
            }
            .stButton > button[kind="secondary"] {
                background-color: #2a2d3e !important;
                border: 1px solid #444 !important;
            }
            .stButton > button[kind="secondary"]:hover {
                background-color: #3a3d4e !important;
                border-color: #2F3AE4 !important;
            }
            
            /* All buttons in dark mode */
            button[kind="primary"],
            button[kind="secondary"] {
                background-color: #2F3AE4 !important;
                color: #ffffff !important;
                border: none !important;
            }
            button[kind="primary"]:hover,
            button[kind="secondary"]:hover {
                background-color: #2535b3 !important;
            }
            button[kind="secondary"] {
                background-color: #2a2d3e !important;
            }
            button[kind="secondary"]:hover {
                background-color: #3a3d4e !important;
            }
            
            /* Radio buttons (tabs) */
            [data-testid="stRadio"] label {
                color: #fafafa !important;
            }
            
            /* Checkbox */
            [data-testid="stCheckbox"] label {
                color: #fafafa !important;
            }
            
            /* Expanders */
            [data-testid="stExpander"] {
                background-color: #1e2130 !important;
                border-color: #333 !important;
            }
            [data-testid="stExpander"] summary {
                color: #fafafa !important;
            }
            [data-testid="stExpander"] div {
                color: #fafafa !important;
            }
            
            /* Code blocks - dark theme */
            .stCodeBlock, [data-testid="stCodeBlock"] {
                background-color: #1e2130 !important;
            }
            .stCodeBlock pre, [data-testid="stCodeBlock"] pre {
                background-color: #1e2130 !important;
                color: #fafafa !important;
            }
            .stCodeBlock code, [data-testid="stCodeBlock"] code {
                color: #fafafa !important;
            }
            
            /* Additional code block targeting */
            code {
                background-color: #1e2130 !important;
                color: #fafafa !important;
            }
            pre {
                background-color: #1e2130 !important;
                color: #fafafa !important;
            }
            pre code {
                background-color: #1e2130 !important;
                color: #fafafa !important;
            }
            
            /* Streamlit code widget */
            .stCode {
                background-color: #1e2130 !important;
            }
            .stCode code {
                color: #fafafa !important;
            }
            
            /* Text inputs - dark theme */
            .stTextInput > div > div > input,
            .stNumberInput > div > div > input,
            .stSelectbox > div > div {
                background-color: #2a2d3e !important;
                color: #fafafa !important;
                border-color: #444 !important;
            }
            
            /* Dataframe - dark theme */
            [data-testid="stDataFrame"] {
                background-color: #1e2130 !important;
            }
            [data-testid="stDataFrame"] * {
                color: #fafafa !important;
            }
            
            /* Dataframe cells */
            .stDataFrame table {
                background-color: #1e2130 !important;
            }
            .stDataFrame th {
                background-color: #2a2d3e !important;
                color: #fafafa !important;
            }
            .stDataFrame td {
                background-color: #1e2130 !important;
                color: #fafafa !important;
            }
            
            /* Charts - dark theme */
            [data-testid="stVegaLiteChart"] {
                background-color: #1e2130 !important;
            }
            canvas {
                background-color: #1e2130 !important;
            }
            
            /* Streamlit line/bar charts */
            [data-testid="stArrowVegaLiteChart"] {
                background-color: transparent !important;
            }
            
            /* Chart container */
            .element-container [data-testid="stVegaLiteChart"] {
                background-color: #1e2130 !important;
                border-radius: 8px;
                padding: 10px;
            }
            
            /* Tables in dark mode */
            .stDataFrame, [data-testid="stTable"] {
                background-color: #1e2130 !important;
                color: #fafafa !important;
            }
            
            /* Table headers and cells */
            .stDataFrame thead tr th {
                background-color: #2a2d3e !important;
                color: #fafafa !important;
                border-color: #444 !important;
            }
            
            .stDataFrame tbody tr td {
                background-color: #1e2130 !important;
                color: #fafafa !important;
                border-color: #333 !important;
            }
            
            .stDataFrame tbody tr:hover {
                background-color: #262938 !important;
            }
            
            /* Form elements */
            [data-testid="stForm"] {
                background-color: #1e2130 !important;
                border-color: #333 !important;
            }
        </style>
        """
    else:
        return """
        <style>
            /* Light theme - Override Streamlit's dark defaults */
            .stApp {
                background-color: #ffffff !important;
                color: #1a1a1a !important;
            }
            
            [data-testid="stSidebar"] {
                background-color: #f8f9fa !important;
            }
            
            [data-testid="stSidebar"] * {
                color: #1a1a1a !important;
            }
            
            [data-testid="stHeader"] {
                background-color: #ffffff !important;
            }
            
            /* Main content text */
            .stApp p, .stApp span, .stApp label, .stApp div {
                color: #1a1a1a;
            }
            
            /* Headers */
            .stApp h1, .stApp h2, .stApp h3, .stApp h4, .stApp h5, .stApp h6 {
                color: #1a1a1a !important;
            }
            
            /* Markdown text */
            [data-testid="stMarkdownContainer"] {
                color: #1a1a1a !important;
            }
            [data-testid="stMarkdownContainer"] p {
                color: #1a1a1a !important;
            }
            
            /* Metrics */
            [data-testid="stMetricValue"] {
                color: #1a1a1a !important;
            }
            [data-testid="stMetricLabel"] {
                color: #555 !important;
            }
            
            /* Selectbox and inputs */
            [data-testid="stSelectbox"] label,
            [data-testid="stTextInput"] label,
            [data-testid="stNumberInput"] label,
            [data-testid="stSlider"] label {
                color: #1a1a1a !important;
            }
            
            .stSelectbox > div > div,
            .stTextInput > div > div > input,
            .stNumberInput > div > div > input {
                background-color: #ffffff !important;
                color: #1a1a1a !important;
                border-color: #ddd !important;
            }
            
            /* Expanders */
            [data-testid="stExpander"] {
                background-color: #f8f9fa !important;
                border-color: #ddd !important;
            }
            [data-testid="stExpander"] summary {
                color: #1a1a1a !important;
            }
            [data-testid="stExpander"] div {
                color: #1a1a1a !important;
            }
            
            /* Dataframe */
            [data-testid="stDataFrame"] {
                background-color: #ffffff !important;
            }
            
            /* Code blocks */
            .stCodeBlock {
                background-color: #f5f5f5 !important;
            }
            
            /* Dividers */
            hr {
                border-color: #ddd !important;
            }
            
            /* Captions */
            .stCaption, small {
                color: #666 !important;
            }
            
            /* Info/Success/Warning/Error boxes */
            [data-testid="stAlert"] {
                background-color: #f0f7ff !important;
                color: #1a1a1a !important;
            }
            
            /* Radio buttons (tab selector) */
            [data-testid="stRadio"] label {
                color: #1a1a1a !important;
            }
            
            /* Checkbox */
            [data-testid="stCheckbox"] label {
                color: #1a1a1a !important;
            }
            
            /* Buttons in sidebar - light theme */
            [data-testid="stSidebar"] button {
                background-color: #e8e8e8 !important;
                color: #1a1a1a !important;
                border: 1px solid #ccc !important;
            }
            [data-testid="stSidebar"] button:hover {
                background-color: #ddd !important;
                border-color: #2F3AE4 !important;
            }
        </style>
        """

# Apply theme CSS
st.markdown(get_theme_css(st.session_state['theme']), unsafe_allow_html=True)

# Custom CSS for improved UI/UX
st.markdown("""
<style>
    /* Hide default Streamlit branding */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    
    /* Rotating logo animation for loading */
    @keyframes rotate {
        from { transform: rotate(0deg); }
        to { transform: rotate(360deg); }
    }
    
    .rotating-logo {
        animation: rotate 1.5s linear infinite;
    }
    
    /* Pulse animation for loading text */
    @keyframes pulse {
        0%, 100% { opacity: 1; }
        50% { opacity: 0.5; }
    }
    
    .pulse {
        animation: pulse 1.5s ease-in-out infinite;
    }
    
    /* Loading overlay styling - clean, no background */
    .loading-overlay {
        text-align: center;
        padding: 2rem;
        border-radius: 12px;
        margin: 1rem 0;
    }
    
    .loading-text {
        color: #2F3AE4;
        font-size: 1.1rem;
        font-weight: 600;
        margin-top: 1rem;
    }
    
    /* Metric value styling */
    [data-testid="stMetricValue"] {
        font-size: 1.8rem;
        font-weight: 700;
    }
    
    /* Button improvements */
    .stButton > button {
        border-radius: 8px;
        font-weight: 600;
    }
    
    /* Primary button highlight */
    .stButton > button[kind="primary"] {
        background: linear-gradient(90deg, #2F3AE4 0%, #5D65F5 100%);
    }
    
    /* Theme toggle button */
    .theme-toggle {
        cursor: pointer;
        padding: 0.5rem 1rem;
        border-radius: 20px;
        border: 1px solid var(--border-color, #333);
        background: transparent;
        transition: all 0.3s ease;
    }
    
    .theme-toggle:hover {
        background: var(--accent-color, #2F3AE4);
        color: white;
    }
</style>
""", unsafe_allow_html=True)

# Helper function to load and encode logo as base64
@st.cache_data
def get_logo_base64():
    """Logo loading disabled for public release"""
    return None

# Custom loading spinner with rotating logo
def show_loading_spinner(message="Loading..."):
    """Display a rotating logo loader"""
    logo_data = get_logo_base64()
    if logo_data:
        st.markdown(f"""
        <div class="loading-overlay">
            <img src="{logo_data}" class="rotating-logo" width="80" height="80" />
            <div class="loading-text pulse">{message}</div>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.spinner(message)

# Initialize components with caching
@st.cache_resource
def init_database():
    """Initialize and cache database connection."""
    try:
        return Database()
    except Exception as e:
        st.error(f"Database initialization failed: {e}")
        return None

@st.cache_resource
def init_collector():
    """Initialize and cache AWS collector."""
    try:
        return CloudWatchCollector()
    except Exception as e:
        st.error(f"AWS Collector initialization failed: {e}")
        return None

@st.cache_resource
def init_analyzer():
    """Initialize and cache OpenAI analyzer."""
    try:
        return LogAnalyzer()
    except ValueError as e:
        st.warning(f"OpenAI not configured: {e}")
        return None
    except Exception as e:
        st.error(f"Analyzer initialization failed: {e}")
        return None

# Initialize components
db = init_database()
collector = init_collector()
analyzer = init_analyzer()

# Auto-discover log groups on first run
if collector and 'log_groups' not in st.session_state:
    try:
        placeholder = st.empty()
        with placeholder.container():
            show_loading_spinner("🔍 Auto-discovering log groups...")
        log_groups = collector.list_log_groups()
        if log_groups:
            st.session_state['log_groups'] = log_groups
            # Fetch metadata for discovered log groups
            metadata = collector.describe_log_groups(log_groups)
            st.session_state['log_groups_metadata'] = metadata
        placeholder.empty()
    except Exception as e:
        # Silently fail on auto-discovery, user can manually trigger later
        pass

# Check if critical components failed
if db is None:
    st.error("⚠️ **Database Connection Failed**")
    st.info("""
    **MySQL is not running or not configured correctly.**
    
    **Quick Fix Options:**
    
    1. **Use Docker MySQL (Easiest):**
       ```bash
       docker-compose up -d mysql
       ```
    
    2. **Or install MySQL locally:**
       - Download from: https://dev.mysql.com/downloads/installer/
       - Set password in .env file
       - Run: `mysql -u root -p < schema.sql`
    
    3. **Check your .env file has:**
       ```
       MYSQL_HOST=localhost
       MYSQL_PASSWORD=your_password
       ```
    """)
    st.stop()

if collector is None:
    st.error("⚠️ **AWS Connection Failed**")
    st.info("Check your AWS credentials in the .env file")
    st.stop()

st.markdown("""
<div style="display: flex; flex-direction: column; justify-content: center; margin-bottom: 1rem;">
    <h1 style="color: #2F3AE4; margin: 0; font-size: 2.2rem; font-weight: 800;">CloudWatch AI Sentinel</h1>
    <p style="color: #888; margin: 0.5rem 0 0 0; font-size: 1rem;">🤖 Intelligent log monitoring powered by AI • Real-time AWS CloudWatch analysis</p>
</div>
""", unsafe_allow_html=True)
st.markdown("<hr style='border: 1px solid #2F3AE4; margin: 1rem 0;'>", unsafe_allow_html=True)

# Sidebar - Configuration
with st.sidebar:
    st.header("⚙️ Configuration")
    
    # Theme Toggle
    col_theme1, col_theme2 = st.columns([3, 1])
    with col_theme1:
        st.caption("Theme")
    with col_theme2:
        theme_icon = "🌙" if st.session_state['theme'] == 'dark' else "☀️"
        if st.button(theme_icon, key="theme_toggle", help="Toggle dark/light mode"):
            st.session_state['theme'] = 'light' if st.session_state['theme'] == 'dark' else 'dark'
            st.rerun()
    
    st.divider()
    
    # Connection Status
    st.subheader("Connection Status")
    col1, col2 = st.columns(2)
    
    with col1:
        if db and db.test_connection():
            st.success("MySQL ✓")
        else:
            st.error("MySQL ✗")
    
    with col2:
        if collector and collector.test_connection():
            st.success("AWS ✓")
        else:
            st.error("AWS ✗")
    
    if analyzer:
        st.success("OpenAI ✓")
    else:
        st.error("OpenAI ✗ (Check API key)")
    
    st.divider()
    
    # Log Group Selection
    st.subheader("📋 Log Selection")
    
    # Option to list available log groups
    if st.button("🔍 Discover Log Groups", width='stretch'):
        placeholder = st.empty()
        with placeholder.container():
            show_loading_spinner("Fetching log groups from AWS...")
        log_groups = collector.list_log_groups()
        placeholder.empty()
        if log_groups:
            st.session_state['log_groups'] = log_groups
            # Fetch metadata for discovered log groups
            metadata = collector.describe_log_groups(log_groups)
            st.session_state['log_groups_metadata'] = metadata
            st.success(f"✅ Found {len(log_groups)} log groups")
        else:
            st.warning("⚠️ No log groups found or connection failed")
    
    # Log group input with metadata display
    if 'log_groups' in st.session_state and st.session_state['log_groups']:
        log_group = st.selectbox(
            "Select Log Group",
            options=st.session_state['log_groups'],
            index=0
        )
        
        # Show metadata for selected log group
        if 'log_groups_metadata' in st.session_state:
            metadata = st.session_state['log_groups_metadata'].get(log_group)
            if metadata:
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("📦 Storage", f"{metadata['stored_mb']} MB")
                with col2:
                    retention = metadata['retention_days']
                    st.metric("⏱️ Retention", f"{retention} days" if isinstance(retention, int) else retention)
                with col3:
                    if metadata['created_time']:
                        days_old = (datetime.now() - metadata['created_time']).days
                        st.metric("📅 Age", f"{days_old} days")
    else:
        log_group = st.text_input(
            "Log Group Name",
            value="/aws/lambda/my-function",
            help="Enter the full CloudWatch log group path"
        )
    
    # Time window
    minutes = st.slider(
        "Time Window (minutes)",
        min_value=5,
        max_value=240,
        value=15,
        step=5,
        help="How far back to search for logs"
    )
    
    st.divider()
    
    # Analysis button
    analyze_disabled = not analyzer or not log_group
    
    if st.button("🔍 Run Analysis", type="primary", width='stretch', disabled=analyze_disabled):
        if not log_group:
            st.error("Please enter a log group name")
        elif not analyzer:
            st.error("OpenAI not configured. Check OPENAI_API_KEY in .env")
        else:
            start = datetime.now()
            
            # Step 1: Fetch logs
            fetch_placeholder = st.empty()
            with fetch_placeholder.container():
                show_loading_spinner("📥 Fetching logs from CloudWatch...")
            raw_logs = collector.fetch_recent_error_logs(log_group, minutes)
            fetch_placeholder.empty()
            
            if not raw_logs:
                st.success("✅ No errors found in the selected time window!")
            elif raw_logs.startswith("Error:") or raw_logs.startswith("Failed"):
                st.error(raw_logs)
            else:
                log_count = len(raw_logs.split('\n'))
                st.info(f"📊 Found {log_count} log entries")
                
                # Check if logs contain real errors before making AI call
                if not analyzer.contains_real_errors(raw_logs):
                    st.warning("⚠️ No real errors detected in logs (just warnings/info). AI analysis skipped to save costs.")
                    with st.expander("📄 View Raw Logs"):
                        st.code(raw_logs, language="log")
                else:
                    # Step 2: AI Analysis (only for real errors)
                    analysis_placeholder = st.empty()
                    with analysis_placeholder.container():
                        show_loading_spinner(f"🤖 AI analyzing {log_count} log entries...")
                        noise_patterns = db.get_noise_patterns()
                        incidents = analyzer.analyze_logs(
                            logs=raw_logs,
                            log_group=log_group,
                            noise_patterns=noise_patterns
                        )
                    analysis_placeholder.empty()
                    
                    # Step 3: Save to database
                    if incidents:
                        save_placeholder = st.empty()
                        with save_placeholder.container():
                            show_loading_spinner("💾 Saving incidents to database...")
                        saved_count = 0
                        for incident in incidents:
                            if db.save_incident(incident):
                                saved_count += 1
                        save_placeholder.empty()
                        
                        # Save analysis run metadata
                        end = datetime.now()
                        duration = (end - start).total_seconds()
                        
                        run = AnalysisRun(
                            log_group=log_group,
                            start_time=start,
                            end_time=end,
                            total_logs=log_count,
                            incidents_found=len(incidents),
                            duration_seconds=duration
                        )
                        db.save_analysis_run(run)
                        
                        st.success(f"✅ Analysis complete! Found {len(incidents)} actionable incidents in {duration:.1f}s")
                    else:
                        st.success("✅ No actionable incidents found (all noise filtered)")
                    
                    st.rerun()
    
    if analyze_disabled:
        if not analyzer:
            st.caption("⚠️ Set OPENAI_API_KEY to enable analysis")

# Initialize active tab in session state
if 'active_tab' not in st.session_state:
    st.session_state['active_tab'] = 0

# Main content area - using session state to preserve active tab
tab_names = ["📊 Dashboard", "🌐 Website Analytics", "💰 Cost Analytics", "🔒 Security", "📈 Performance", "🏥 Health", "📋 Compliance", "⚠️ Quotas", "🔄 Backups", "📜 Incident History", "📋 Raw Logs", "⚙️ Settings"]

# Create tabs - note: we can't directly set which tab is active, so we use a workaround
# The workaround is to use st.radio as a tab selector
selected_tab = st.radio(
    "Navigation",
    options=tab_names,
    index=st.session_state.get('active_tab', 0),
    horizontal=True,
    label_visibility="collapsed",
    key="tab_selector"
)

# Update active tab index
st.session_state['active_tab'] = tab_names.index(selected_tab)

# Display content based on selected tab
if selected_tab == "📊 Dashboard":
    st.header("Recent Incidents (Last 24 Hours)")
    
    # CloudWatch Incidents Metrics
    st.subheader("🛡️ CloudWatch Incidents")
    stats = db.get_stats()
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("🔴 Critical", stats.get('critical', 0))
    col2.metric("🟡 Warnings", stats.get('warnings', 0))
    col3.metric("📊 Total", stats.get('total_incidents', 0))
    col4.metric("⚠️ Unresolved", stats.get('unresolved', 0))
    
    st.divider()
    
    # Website Analytics Summary
    logo_data = get_logo_base64()
    if logo_data:
        col_logo, col_title = st.columns([0.4, 9.6])
        with col_logo:
            st.image(logo_data, width=35)
        with col_title:
            st.markdown("""
            <div style="display: flex; align-items: center; height: 35px; margin-left: -15px;">
                <h3 style="margin: 0; font-size: 1.4rem;">Production Website (Today)</h3>
            </div>
            """, unsafe_allow_html=True)
    else:
        st.subheader("🌐 Production Website (Today)")
    
    try:
        cf_analytics = CloudFrontAnalytics()
        today_stats = cf_analytics.get_today_stats()
        
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("👥 Unique Visitors", f"{today_stats['unique_visitors']:,}")
        col2.metric("📄 Page Views", f"{today_stats['total_page_views']:,}")
        col3.metric("📊 Total Requests", f"{today_stats['total_requests']:,}")
        
        # Format bytes
        bytes_mb = today_stats['total_bytes'] / (1024 * 1024)
        col4.metric("📦 Data Served", f"{bytes_mb:.1f} MB")
        
        # Show top pages if available
        if today_stats['top_pages']:
            st.caption("📌 Top Pages Today:")
            top_3 = today_stats['top_pages'][:3]
            for uri, views in top_3:
                st.text(f"  • {uri}: {views} views")
    except Exception as e:
        st.info("🌐 Website analytics will appear here once CloudFront logs are available (1-3 hours after enabling)")
        st.caption(f"Note: {str(e)}")
    
    st.divider()
    
    # Filters
    col1, col2 = st.columns(2)
    with col1:
        filter_severity = st.selectbox(
            "Filter by Severity",
            options=["All", "CRITICAL", "WARNING", "INFO"],
            index=0,
            key="dashboard_severity"
        )
    
    # Fetch incidents
    incidents = db.get_recent_incidents(
        hours=24,
        severity=None if filter_severity == "All" else filter_severity
    )
    
    if not incidents:
        st.info("🎉 No incidents recorded yet. Run an analysis to get started.")
    else:
        # Display incidents
        severity_icons = {
            "CRITICAL": "🔴",
            "WARNING": "🟡",
            "INFO": "ℹ️"
        }
        
        for inc in incidents:
            icon = severity_icons.get(inc['severity'], "❓")
            status = "✓ Resolved" if inc['resolved'] else "⚠️ Active"
            timestamp_str = inc['timestamp'].strftime("%Y-%m-%d %H:%M:%S") if inc['timestamp'] else ""
            
            count_suffix = f" ({inc['occurrence_count']}x)" if inc.get('occurrence_count', 1) > 1 else ""
            
            with st.expander(
                f"{icon} [{inc['severity']}] {inc['summary']}{count_suffix}",
                expanded=not inc['resolved']
            ):
                col1, col2 = st.columns([3, 1])
                
                with col1:
                    st.markdown(f"**🔍 Root Cause:** {inc['root_cause']}")
                    st.markdown(f"**💡 Recommendation:** {inc['recommendation']}")
                    st.markdown(f"**🏷️ Service:** {inc['affected_service']}")
                    
                    if inc.get('occurrence_count', 1) > 1:
                        last_seen_str = inc['last_seen'].strftime("%Y-%m-%d %H:%M:%S") if inc.get('last_seen') else "Unknown"
                        st.warning(f"🔄 This incident has occurred **{inc['occurrence_count']} times**. Last seen: {last_seen_str}")
                    
                    st.caption(f"📁 Log Group: `{inc['log_group']}`")
                    st.caption(f"🕐 First detected: {timestamp_str}")
                    
                    # Display raw logs if available
                    if inc.get('raw_logs'):
                        import json
                        with st.expander("📄 View Raw Logs"):
                            try:
                                raw_logs = json.loads(inc['raw_logs']) if isinstance(inc['raw_logs'], str) else inc['raw_logs']
                                if isinstance(raw_logs, list):
                                    for i, log_entry in enumerate(raw_logs[:20]):  # Limit to first 20
                                        st.code(log_entry, language=None)
                                    if len(raw_logs) > 20:
                                        st.caption(f"... and {len(raw_logs) - 20} more log entries")
                                else:
                                    st.code(str(raw_logs), language=None)
                            except:
                                st.text(str(inc['raw_logs'])[:1000])
                
                with col2:
                    if not inc['resolved']:
                        if st.button("✓ Resolve", key=f"resolve_{inc['id']}", type="primary"):
                            if db.mark_resolved(inc['id']):
                                st.success("Marked as resolved!")
                                st.rerun()
                    else:
                        st.success(status)

elif selected_tab == "🌐 Website Analytics":
    # Header with logo
    logo_data = get_logo_base64()
    if logo_data:
        col_logo, col_title = st.columns([0.5, 9.5])
        with col_logo:
            st.image(logo_data, width=40)
        with col_title:
            st.markdown("""
            <div style="display: flex; align-items: center; height: 40px; margin-left: -20px;">
                <h2 style="margin: 0; font-size: 1.8rem;">Production Website Analytics</h2>
            </div>
            """, unsafe_allow_html=True)
    else:
        st.header("🌐 Production Website Analytics")
    
    st.divider()
    
    st.info("📅 Analytics data available from January 1st, 2026 onwards")
    
    try:
        cf_analytics = CloudFrontAnalytics()
        
        # Time range selector and refresh button
        col1, col2 = st.columns([4, 1])
        with col1:
            time_range = st.selectbox(
                "Time Range",
                options=[1, 7, 14, 30],
                format_func=lambda x: f"Last {x} day" if x == 1 else f"Last {x} days",
                index=1  # Default to 7 days
            )
        
        with col2:
            st.markdown("<div style='padding-top: 26px;'></div>", unsafe_allow_html=True)
            if st.button("🔄 Refresh", type="secondary", width='stretch'):
                st.rerun()
        
        # Fetch stats
        with st.spinner(f"Analyzing CloudFront logs for the last {time_range} day(s)..."):
            stats = cf_analytics.get_recent_stats(days=time_range)
        
        # Summary metrics
        st.subheader("📊 Overview")
        col1, col2, col3, col4 = st.columns(4)
        
        col1.metric(
            "👥 Unique Visitors",
            f"{stats['unique_visitors']:,}",
            help="Number of unique IP addresses"
        )
        col2.metric(
            "📄 Page Views",
            f"{stats['total_page_views']:,}",
            help="Total page views (excluding assets)"
        )
        col3.metric(
            "📊 Total Requests",
            f"{stats['total_requests']:,}",
            help="All requests including assets"
        )
        
        bytes_gb = stats['total_bytes'] / (1024 * 1024 * 1024)
        col4.metric(
            "💾 Data Served",
            f"{bytes_gb:.2f} GB",
            help="Total data transferred"
        )
        
        st.divider()
        
        # Two column layout for details
        col1, col2 = st.columns(2)
        
        with col1:
            # Top Pages
            st.subheader("📌 Top Pages")
            if stats['top_pages']:
                for i, (uri, views) in enumerate(stats['top_pages'], 1):
                    st.metric(
                        label=f"{i}. {uri}",
                        value=f"{views:,} views"
                    )
            else:
                st.info("No page data available yet")
        
        with col2:
            # Top Referrers
            st.subheader("🔗 Top Referrers")
            if stats['top_referrers']:
                for i, (referrer, visits) in enumerate(stats['top_referrers'], 1):
                    # Simplify referrer display
                    display_ref = referrer
                    if len(display_ref) > 50:
                        display_ref = display_ref[:50] + "..."
                    st.metric(
                        label=f"{i}. {display_ref}",
                        value=f"{visits:,} visits"
                    )
            else:
                st.info("No referrer data available yet")
        
        st.divider()
        
        # Two column layout for tables - ensures alignment
        col1, col2 = st.columns(2)
        
        with col1:
            # Browser breakdown
            st.subheader("🌐 Browsers")
            if stats['browsers']:
                import pandas as pd
                browser_df = pd.DataFrame(stats['browsers'], columns=['Browser', 'Visits'])
                st.dataframe(
                    browser_df,
                    width='stretch',
                    hide_index=True,
                    column_config={
                        "Browser": st.column_config.TextColumn("Browser", width="medium"),
                        "Visits": st.column_config.NumberColumn("Visits", width="small", format="%d")
                    }
                )
            else:
                st.info("No browser data available yet")
        
        with col2:
            # Status codes
            st.subheader("📡 Status Codes")
            if stats['status_codes']:
                import pandas as pd
                status_df = pd.DataFrame(
                    [(str(code), count) for code, count in sorted(stats['status_codes'].items())],
                    columns=['Status Code', 'Count']
                )
                st.dataframe(
                    status_df,
                    width='stretch',
                    hide_index=True,
                    column_config={
                        "Status Code": st.column_config.TextColumn("Status Code", width="medium"),
                        "Count": st.column_config.NumberColumn("Count", width="small", format="%d")
                    }
                )
            else:
                st.info("No status code data available yet")
        
        st.divider()
        
        # Traffic over time
        if stats['daily_traffic']:
            st.subheader("📈 Daily Traffic")
            import pandas as pd
            
            daily_df = pd.DataFrame(stats['daily_traffic'], columns=['Date', 'Requests'])
            st.line_chart(daily_df.set_index('Date'))
        
        # Info footer
        st.divider()
        st.caption(f"📝 Analyzed {stats['log_files_processed']} log file(s) | CloudFront logs are updated hourly")
        
        if stats['total_requests'] == 0:
            st.info("""
            ℹ️ **No data available yet**
            
            CloudFront access logs were recently enabled. Logs are generated hourly and 
            typically appear 1-3 hours after enabling. Please check back later.
            
            Log location: `s3://example-cloudfront-logs/cloudfront/`
            """)
    
    except Exception as e:
        st.error(f"Error loading website analytics: {str(e)}")
        st.info("Website analytics will be available once CloudFront logs start being generated (1-3 hours after enabling)")

elif selected_tab == "💰 Cost Analytics":
    st.header("💰 AWS Cost Analytics")
    st.caption("AI-powered cost analysis and optimization recommendations")
    
    try:
        cost_analyzer = AWSCostAnalyzer()
        
        # Test connection
        if not cost_analyzer.test_connection():
            st.error("❌ Unable to connect to AWS Cost Explorer. Ensure your AWS credentials have `ce:*` permissions.")
            st.info("""
            **Required IAM Permissions:**
            ```json
            {
                "Effect": "Allow",
                "Action": [
                    "ce:GetCostAndUsage",
                    "ce:GetCostForecast",
                    "ce:GetRightsizingRecommendation",
                    "ce:GetSavingsPlansPurchaseRecommendation",
                    "ce:GetAnomalyMonitors",
                    "ce:GetAnomalies"
                ],
                "Resource": "*"
            }
            ```
            """)
        else:
            # Get available months for selection
            from calendar import month_name as cal_month_name
            today = datetime.now()
            
            # Generate list of last 12 months
            month_options = []
            for i in range(12):
                m = today.month - i
                y = today.year
                while m <= 0:
                    m += 12
                    y -= 1
                month_label = f"{cal_month_name[m]} {y}"
                month_options.append({'label': month_label, 'year': y, 'month': m})
            
            # Month selector with aligned button
            col1, col2 = st.columns([3, 1])
            with col1:
                selected_month_idx = st.selectbox(
                    "Select Month",
                    options=range(len(month_options)),
                    format_func=lambda x: month_options[x]['label'],
                    index=0,
                    key="cost_month"
                )
                selected_month = month_options[selected_month_idx]
            
            with col2:
                st.markdown("<br>", unsafe_allow_html=True)  # Spacer to align with selectbox label
                analyze_clicked = st.button("🔍 Analyze Costs", type="primary", use_container_width=True)
            
            # Initialize session state for cost data
            if 'cost_data' not in st.session_state:
                st.session_state['cost_data'] = None
            if 'cost_ai_analysis' not in st.session_state:
                st.session_state['cost_ai_analysis'] = None
            if 'cost_architecture' not in st.session_state:
                st.session_state['cost_architecture'] = None
            if 'cost_month_history' not in st.session_state:
                st.session_state['cost_month_history'] = None
            
            if analyze_clicked:
                year = selected_month['year']
                month = selected_month['month']
                
                with st.spinner(f"📊 Fetching cost data for {selected_month['label']}..."):
                    cost_data = cost_analyzer.get_cost_summary(year=year, month=month)
                    st.session_state['cost_data'] = cost_data
                    
                    if not cost_data.get('error'):
                        # Get month-over-month changes
                        cost_data['cost_changes'] = cost_analyzer.get_month_over_month_changes(year, month)
                        
                        # Get multi-month history for trend
                        with st.spinner("📈 Loading monthly trends..."):
                            month_history = cost_analyzer.get_multi_month_summary(6)
                            st.session_state['cost_month_history'] = month_history
                        
                        # Get forecast only if analyzing current or recent month
                        if selected_month_idx <= 1:
                            cost_data['forecast'] = cost_analyzer.get_cost_forecast(30)
                        
                        with st.spinner("🔍 Discovering AWS architecture..."):
                            architecture = cost_analyzer.discover_architecture()
                            st.session_state['cost_architecture'] = architecture
                        
                        with st.spinner("🤖 AI analyzing costs and architecture..."):
                            ai_analysis = cost_analyzer.analyze_costs_with_ai(cost_data, architecture)
                            st.session_state['cost_ai_analysis'] = ai_analysis
                        
                        st.success("✅ Cost analysis complete!")
            
            # Display cost data if available
            cost_data = st.session_state.get('cost_data')
            
            if cost_data and not cost_data.get('error'):
                # Period indicator
                period_label = cost_data.get('period_label', f"{cost_data.get('start_date')} to {cost_data.get('end_date')}")
                st.caption(f"📅 Analyzing: **{period_label}** ({cost_data.get('start_date')} to {cost_data.get('end_date')})")
                
                # Monthly trend chart (if available)
                month_history = st.session_state.get('cost_month_history')
                if month_history:
                    st.subheader("📊 Monthly Cost Trend")
                    import pandas as pd
                    
                    # Prepare data (reverse to show chronological order)
                    trend_data = [{'Month': m['month_name'], 'Cost ($)': m['total_cost']} 
                                  for m in reversed(month_history) if not m.get('error')]
                    
                    if trend_data:
                        trend_df = pd.DataFrame(trend_data)
                        st.bar_chart(trend_df.set_index('Month'))
                    
                    st.divider()
                
                # Cost Overview Metrics
                st.subheader("📈 Cost Overview")
                col1, col2, col3, col4 = st.columns(4)
                
                # Calculate month-over-month change
                changes = cost_data.get('cost_changes', {})
                mom_change = changes.get('total_change', 0)
                mom_pct = changes.get('total_change_percent', 0)
                
                with col1:
                    st.metric(
                        "💵 Total Cost",
                        f"${cost_data['total_cost']:,.2f}",
                        delta=f"${mom_change:+,.2f} ({mom_pct:+.1f}%)" if mom_change != 0 else None,
                        delta_color="inverse" if mom_change > 0 else "normal",
                        help=f"Total unblended cost for {period_label}"
                    )
                with col2:
                    st.metric(
                        "📅 Daily Average",
                        f"${cost_data['avg_daily_cost']:,.2f}",
                        help="Average cost per day"
                    )
                with col3:
                    prev_total = changes.get('previous_total', 0)
                    if prev_total > 0:
                        st.metric(
                            "📆 Previous Month",
                            f"${prev_total:,.2f}",
                            help=f"Cost for {changes.get('previous_month', 'previous month')}"
                        )
                    else:
                        forecast = cost_data.get('forecast', {})
                        if forecast and not forecast.get('error'):
                            st.metric(
                                "🔮 30-Day Forecast",
                                f"${forecast['forecasted_total']:,.2f}",
                                help="Projected cost for next 30 days"
                            )
                        else:
                            st.metric("🔮 Forecast", "N/A")
                with col4:
                    changes = cost_data.get('cost_changes', {}).get('changes', [])
                    if changes:
                        total_change = sum(c['change_amount'] for c in changes)
                        delta_color = "normal" if total_change <= 0 else "inverse"
                        st.metric(
                            "📊 Period Change",
                            f"${abs(total_change):,.2f}",
                            delta=f"{'↑' if total_change > 0 else '↓'} vs prev period",
                            delta_color=delta_color
                        )
                    else:
                        st.metric("📊 Period Change", "N/A")
                
                st.divider()
                
                # Two columns: Service Breakdown and Daily Trend
                col1, col2 = st.columns(2)
                
                with col1:
                    st.subheader("🏷️ Cost by Service")
                    service_breakdown = cost_data.get('service_breakdown', [])
                    if service_breakdown:
                        import pandas as pd
                        
                        # Prepare data for chart
                        services_df = pd.DataFrame(service_breakdown[:10])  # Top 10 services
                        
                        # Display as bar chart
                        chart_data = pd.DataFrame({
                            'Service': [s['service'][:30] + '...' if len(s['service']) > 30 else s['service'] for s in service_breakdown[:10]],
                            'Cost ($)': [s['cost'] for s in service_breakdown[:10]]
                        })
                        st.bar_chart(chart_data.set_index('Service'))
                        
                        # Table with details
                        with st.expander("📋 View Full Service Breakdown"):
                            for svc in service_breakdown:
                                pct = (svc['cost'] / cost_data['total_cost'] * 100) if cost_data['total_cost'] > 0 else 0
                                st.text(f"${svc['cost']:>10,.2f} ({pct:>5.1f}%)  {svc['service']}")
                    else:
                        st.info("No service breakdown available")
                
                with col2:
                    st.subheader("📈 Daily Cost Trend")
                    daily_costs = cost_data.get('daily_costs', [])
                    if daily_costs:
                        import pandas as pd
                        
                        daily_df = pd.DataFrame(daily_costs)
                        daily_df['date'] = pd.to_datetime(daily_df['date'])
                        daily_df = daily_df.set_index('date')
                        
                        st.line_chart(daily_df['cost'])
                    else:
                        st.info("No daily cost data available")
                
                st.divider()
                
                # Cost Changes Section (Month-over-Month)
                changes = cost_data.get('cost_changes', {})
                if changes and changes.get('changes'):
                    st.subheader("📊 Month-over-Month Cost Changes")
                    
                    # Show comparison months
                    current_month = changes.get('current_month', '')
                    previous_month = changes.get('previous_month', '')
                    if current_month and previous_month:
                        st.caption(f"Comparing **{current_month}** vs **{previous_month}**")
                    else:
                        st.caption(f"Comparing {changes.get('current_period', '')} vs {changes.get('previous_period', '')}")
                    
                    # Total change summary
                    total_change = changes.get('total_change', 0)
                    total_pct = changes.get('total_change_percent', 0)
                    if total_change != 0:
                        change_icon = "📈" if total_change > 0 else "📉"
                        change_color = "🔴" if total_change > 0 else "🟢"
                        st.markdown(f"**{change_color} Overall Change: {change_icon} ${total_change:+,.2f} ({total_pct:+.1f}%)**")
                    
                    st.markdown("---")
                    
                    col1, col2 = st.columns(2)
                    
                    increases = [c for c in changes['changes'] if c['change_amount'] > 0]
                    decreases = [c for c in changes['changes'] if c['change_amount'] < 0]
                    
                    with col1:
                        st.markdown("**🔺 Cost Increases**")
                        if increases:
                            for change in increases[:7]:
                                pct_display = f"+{change['change_percent']:.1f}%" if change['change_percent'] < 1000 else "NEW"
                                st.markdown(f"- **{change['service'][:35]}**")
                                st.caption(f"  +${change['change_amount']:,.2f} ({pct_display}) | ${change['previous_cost']:,.2f} → ${change['current_cost']:,.2f}")
                        else:
                            st.success("✅ No cost increases this month!")
                    
                    with col2:
                        st.markdown("**🔻 Cost Decreases**")
                        if decreases:
                            for change in decreases[:7]:
                                st.markdown(f"- **{change['service'][:35]}**")
                                st.caption(f"  ${change['change_amount']:,.2f} ({change['change_percent']:.1f}%) | ${change['previous_cost']:,.2f} → ${change['current_cost']:,.2f}")
                        else:
                            st.info("No cost decreases this month")
                
                st.divider()
                
                # Architecture Summary Section
                architecture = st.session_state.get('cost_architecture')
                if architecture:
                    with st.expander("🏗️ Discovered AWS Architecture", expanded=False):
                        col1, col2, col3, col4 = st.columns(4)
                        
                        with col1:
                            ec2_count = len(architecture.get('ec2_instances', []))
                            st.metric("EC2 Instances", ec2_count)
                            rds_count = len(architecture.get('rds_databases', []))
                            st.metric("RDS Databases", rds_count)
                        
                        with col2:
                            lambda_count = len(architecture.get('lambda_functions', []))
                            st.metric("Lambda Functions", lambda_count)
                            s3_count = len(architecture.get('s3_buckets', []))
                            st.metric("S3 Buckets", s3_count)
                        
                        with col3:
                            cf_count = len(architecture.get('cloudfront_distributions', []))
                            st.metric("CloudFront Dists", cf_count)
                            cache_count = len(architecture.get('elasticache_clusters', []))
                            st.metric("ElastiCache", cache_count)
                        
                        with col4:
                            api_count = len(architecture.get('api_gateways', []))
                            st.metric("API Gateways", api_count)
                            lb_count = len(architecture.get('load_balancers', []))
                            st.metric("Load Balancers", lb_count)
                        
                        st.divider()
                        
                        # Show details in tabs
                        arch_tabs = st.tabs(["EC2", "RDS", "Lambda", "S3", "Other"])
                        
                        with arch_tabs[0]:
                            instances = architecture.get('ec2_instances', [])
                            if instances:
                                for inst in instances:
                                    st.markdown(f"**{inst.get('name', 'Unnamed')}** (`{inst['id']}`)")
                                    st.caption(f"Type: {inst['type']} | State: {inst['state']} | AZ: {inst.get('az', 'N/A')}")
                            else:
                                st.info("No EC2 instances found")
                        
                        with arch_tabs[1]:
                            databases = architecture.get('rds_databases', [])
                            if databases:
                                for db in databases:
                                    multi_az = "✅ Multi-AZ" if db.get('multi_az') else "Single-AZ"
                                    st.markdown(f"**{db['id']}** - {db['engine']} {db.get('engine_version', '')}")
                                    st.caption(f"Class: {db['class']} | Storage: {db.get('storage_gb', '?')}GB {db.get('storage_type', '')} | {multi_az}")
                            else:
                                st.info("No RDS databases found")
                        
                        with arch_tabs[2]:
                            functions = architecture.get('lambda_functions', [])
                            if functions:
                                for func in functions[:20]:
                                    st.markdown(f"**{func['name']}**")
                                    st.caption(f"Runtime: {func.get('runtime', 'N/A')} | Memory: {func.get('memory_mb', '?')}MB | Timeout: {func.get('timeout', '?')}s")
                                if len(functions) > 20:
                                    st.caption(f"... and {len(functions) - 20} more functions")
                            else:
                                st.info("No Lambda functions found")
                        
                        with arch_tabs[3]:
                            buckets = architecture.get('s3_buckets', [])
                            if buckets:
                                for bucket in buckets:
                                    st.markdown(f"• {bucket['name']}")
                            else:
                                st.info("No S3 buckets found")
                        
                        with arch_tabs[4]:
                            # CloudFront
                            distributions = architecture.get('cloudfront_distributions', [])
                            if distributions:
                                st.markdown("**CloudFront Distributions**")
                                for dist in distributions:
                                    st.caption(f"• {dist['id']} - {dist.get('domain', 'N/A')}")
                            
                            # Load Balancers
                            lbs = architecture.get('load_balancers', [])
                            if lbs:
                                st.markdown("**Load Balancers**")
                                for lb in lbs:
                                    st.caption(f"• {lb['name']} ({lb.get('type', 'N/A')})")
                            
                            # ECS
                            services = architecture.get('ecs_services', [])
                            if services:
                                st.markdown("**ECS Services**")
                                for svc in services:
                                    st.caption(f"• {svc['name']} (Cluster: {svc['cluster']})")
                            
                            # DynamoDB
                            tables = architecture.get('dynamodb_tables', [])
                            if tables:
                                st.markdown("**DynamoDB Tables**")
                                for table in tables:
                                    st.caption(f"• {table['name']} ({table.get('item_count', 0):,} items)")
                
                st.divider()
                
                # AI Analysis Section
                st.subheader("🤖 AI-Powered Cost Analysis")
                st.caption("Analysis based on your cost data AND discovered AWS architecture")
                ai_analysis = st.session_state.get('cost_ai_analysis')
                
                if ai_analysis:
                    # Escape dollar signs to prevent LaTeX interpretation
                    ai_analysis_escaped = ai_analysis.replace('$', '\\$')
                    st.markdown(ai_analysis_escaped)
                else:
                    st.info("Click 'Analyze Costs' to generate AI-powered insights and recommendations.")
                
            elif cost_data and cost_data.get('error'):
                st.error(f"Error fetching cost data: {cost_data['error']}")
            else:
                st.info("👆 Select a time period and click 'Analyze Costs' to view your AWS spending breakdown with AI insights.")
                
                # Show what this feature provides
                with st.expander("ℹ️ What can Cost Analytics do?"):
                    st.markdown("""
                    **AWS Cost Analytics** provides:
                    
                    - 💵 **Cost Overview**: Total spend, daily averages, and trends
                    - 🏷️ **Service Breakdown**: See which AWS services cost the most
                    - 📈 **Daily Trends**: Visualize your spending over time
                    - 🔮 **Cost Forecasting**: Predict future spending
                    - 📊 **Period Comparison**: Compare costs vs previous period
                    - 🏗️ **Architecture Discovery**: Automatically discovers your AWS resources
                    - 🤖 **AI Analysis**: Context-aware recommendations based on your actual architecture
                    
                    **Requirements**: AWS credentials with Cost Explorer (`ce:*`) and read access to services.
                    """)
    
    except Exception as e:
        st.error(f"Error initializing Cost Analyzer: {str(e)}")
        st.info("Ensure your AWS credentials have Cost Explorer permissions.")

# ============================================
# 🔒 SECURITY ANALYZER TAB
# ============================================
elif selected_tab == "🔒 Security":
    st.header("🔒 Security Analyzer")
    st.caption("Scan for security misconfigurations across AWS services")
    
    # Initialize security analyzer
    @st.cache_resource
    def init_security_analyzer():
        return AWSSecurityAnalyzer()
    
    try:
        security_analyzer = init_security_analyzer()
        
        # Controls
        col1, col2 = st.columns([3, 1])
        with col1:
            st.markdown("Scan security groups, S3 buckets, IAM policies, credentials, and SSL certificates.")
        with col2:
            run_scan = st.button("🔍 Run Security Scan", type="primary", use_container_width=True)
        
        if run_scan:
            with st.spinner("Running comprehensive security scan..."):
                results = security_analyzer.run_full_scan()
                st.session_state['security_results'] = results
                
                # Get AI recommendations
                all_findings = (
                    results.get('security_groups', []) +
                    results.get('s3_buckets', []) +
                    results.get('iam_policies', []) +
                    results.get('unused_credentials', []) +
                    results.get('ssl_certificates', [])
                )
                if all_findings:
                    ai_recs = security_analyzer.get_ai_recommendations(all_findings)
                    st.session_state['security_ai_recs'] = ai_recs
        
        # Display results
        if 'security_results' in st.session_state:
            results = st.session_state['security_results']
            summary = results.get('summary', {})
            
            # Security Score
            all_findings = (
                results.get('security_groups', []) +
                results.get('s3_buckets', []) +
                results.get('iam_policies', []) +
                results.get('unused_credentials', []) +
                results.get('ssl_certificates', [])
            )
            score = security_analyzer.get_security_score(all_findings)
            
            # Score display with color
            if score >= 80:
                score_color = "🟢"
                score_status = "GOOD"
            elif score >= 60:
                score_color = "🟡"
                score_status = "FAIR"
            elif score >= 40:
                score_color = "🟠"
                score_status = "NEEDS ATTENTION"
            else:
                score_color = "🔴"
                score_status = "CRITICAL"
            
            st.subheader(f"{score_color} Security Score: {score}/100 ({score_status})")
            
            # Metrics
            col1, col2, col3, col4, col5 = st.columns(5)
            col1.metric("🔴 Critical", summary.get('critical', 0))
            col2.metric("🟠 High", summary.get('high', 0))
            col3.metric("🟡 Medium", summary.get('medium', 0))
            col4.metric("🟢 Low", summary.get('low', 0))
            col5.metric("📊 Total", summary.get('total_findings', 0))
            
            st.divider()
            
            # Findings by category
            categories = [
                ("🛡️ Security Groups", results.get('security_groups', []), "Misconfigured security groups allowing risky access"),
                ("🪣 S3 Buckets", results.get('s3_buckets', []), "Public buckets or missing encryption"),
                ("👤 IAM Policies", results.get('iam_policies', []), "Overly permissive IAM configurations"),
                ("🔑 Unused Credentials", results.get('unused_credentials', []), "Stale access keys and unused credentials"),
                ("📜 SSL Certificates", results.get('ssl_certificates', []), "Expiring or invalid certificates")
            ]
            
            for title, findings, description in categories:
                with st.expander(f"{title} ({len(findings)} findings)", expanded=len(findings) > 0):
                    st.caption(description)
                    if findings:
                        for finding in findings[:20]:  # Limit display
                            severity = finding.get('severity', 'LOW')
                            sev_icon = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}.get(severity, '⚪')
                            
                            st.markdown(f"""
                            **{sev_icon} {finding.get('title', 'Unknown')}**
                            - **Resource**: `{finding.get('resource_id', 'N/A')}`
                            - **Type**: {finding.get('type', 'N/A')}
                            - **Recommendation**: {finding.get('recommendation', 'N/A')}
                            """)
                            st.divider()
                    else:
                        st.success("✅ No issues found")
            
            # Service status
            if results.get('service_status'):
                with st.expander("⚠️ Service Access Issues"):
                    for service, status in results['service_status'].items():
                        st.warning(f"**{service}**: {status}")
            
            # AI Recommendations
            st.divider()
            st.subheader("🤖 AI Security Recommendations")
            if 'security_ai_recs' in st.session_state and st.session_state['security_ai_recs']:
                st.markdown(st.session_state['security_ai_recs'])
            else:
                st.info("Run a scan to generate AI-powered security recommendations.")
        
        else:
            st.info("👆 Click 'Run Security Scan' to analyze your AWS security posture")
            
            with st.expander("ℹ️ What does Security Analyzer check?"):
                st.markdown("""
                **Security Analyzer** scans for:
                
                - 🛡️ **Security Groups**: Open ports, overly permissive rules
                - 🪣 **S3 Buckets**: Public access, missing encryption, versioning
                - 👤 **IAM Policies**: Admin access, wildcard permissions, MFA status
                - 🔑 **Credentials**: Old access keys, unused credentials
                - 📜 **SSL/TLS**: Expiring certificates, validation issues
                
                **AI Analysis**: Get prioritized remediation recommendations.
                """)
    
    except Exception as e:
        st.error(f"Error initializing Security Analyzer: {str(e)}")

# ============================================
# 📈 PERFORMANCE ANALYZER TAB
# ============================================
elif selected_tab == "📈 Performance":
    st.header("📈 Performance Insights")
    st.caption("Analyze Lambda, RDS, EC2, and API Gateway performance")
    
    @st.cache_resource
    def init_performance_analyzer():
        return AWSPerformanceAnalyzer()
    
    try:
        perf_analyzer = init_performance_analyzer()
        
        # Controls
        col1, col2, col3 = st.columns([2, 1, 1])
        with col1:
            analysis_hours = st.selectbox("Analysis Period", [6, 12, 24, 48, 72], index=2, format_func=lambda x: f"Last {x} hours")
        with col2:
            st.write("")  # Spacer
        with col3:
            run_analysis = st.button("🔍 Analyze Performance", type="primary", use_container_width=True)
        
        if run_analysis:
            with st.spinner("Analyzing performance metrics..."):
                results = perf_analyzer.run_full_analysis(hours=analysis_hours)
                st.session_state['perf_results'] = results
                
                ai_recs = perf_analyzer.get_ai_recommendations(results)
                st.session_state['perf_ai_recs'] = ai_recs
        
        if 'perf_results' in st.session_state:
            results = st.session_state['perf_results']
            summary = results.get('summary', {})
            score = perf_analyzer.get_performance_score(results)
            
            # Score display
            if score >= 80:
                score_color = "🟢"
            elif score >= 60:
                score_color = "🟡"
            else:
                score_color = "🔴"
            
            st.subheader(f"{score_color} Performance Score: {score}/100")
            
            # Summary metrics
            col1, col2, col3 = st.columns(3)
            col1.metric("📊 Resources Analyzed", summary.get('total_resources_analyzed', 0))
            col2.metric("⚠️ With Issues", summary.get('resources_with_issues', 0))
            col3.metric("🔧 Services", len(summary.get('services_analyzed', [])))
            
            st.divider()
            
            # Lambda Analysis
            lambda_data = results.get('lambda', {})
            with st.expander(f"⚡ Lambda Functions ({lambda_data.get('total_functions', 0)} functions)", expanded=True):
                insights = lambda_data.get('insights', [])
                if insights:
                    for func in insights[:10]:
                        cold_start = func.get('cold_start_likelihood', 'LOW')
                        cs_icon = {'HIGH': '🔴', 'MEDIUM': '🟡', 'LOW': '🟢'}.get(cold_start, '⚪')
                        
                        cols = st.columns([3, 1, 1, 1, 1])
                        cols[0].write(f"**{func['function_name']}**")
                        cols[1].metric("Invocations", f"{func['total_invocations']:,}")
                        cols[2].metric("Avg Duration", f"{func['avg_duration_ms']:.0f}ms")
                        cols[3].metric("Error Rate", f"{func['error_rate']}%")
                        cols[4].metric("Cold Start", f"{cs_icon} {cold_start}")
                        
                        if func.get('recommendations'):
                            for rec in func['recommendations']:
                                st.warning(f"💡 {rec['message']}: {rec['suggestion']}")
                        st.divider()
                else:
                    st.info("No Lambda functions found or no metrics available")
            
            # RDS Analysis
            rds_data = results.get('rds', {})
            with st.expander(f"🗄️ RDS Instances ({rds_data.get('total_instances', 0)} instances)"):
                insights = rds_data.get('insights', [])
                if insights:
                    for db in insights:
                        st.write(f"**{db['db_identifier']}** ({db['engine']} - {db['instance_class']})")
                        metrics = db.get('metrics', {})
                        cols = st.columns(4)
                        cols[0].metric("CPU Avg", f"{metrics.get('CPUUtilization', {}).get('average', 0):.1f}%")
                        cols[1].metric("Connections", f"{metrics.get('DatabaseConnections', {}).get('average', 0):.0f}")
                        cols[2].metric("Read IOPS", f"{metrics.get('ReadIOPS', {}).get('average', 0):.0f}")
                        cols[3].metric("Write IOPS", f"{metrics.get('WriteIOPS', {}).get('average', 0):.0f}")
                        
                        for rec in db.get('recommendations', []):
                            st.warning(f"💡 {rec['message']}: {rec['suggestion']}")
                        st.divider()
                else:
                    st.info("No RDS instances found")
            
            # EC2 Analysis
            ec2_data = results.get('ec2', {})
            with st.expander(f"💻 EC2 Instances ({ec2_data.get('total_instances', 0)} instances)"):
                insights = ec2_data.get('insights', [])
                if insights:
                    for instance in insights:
                        st.write(f"**{instance['instance_name']}** ({instance['instance_id']} - {instance['instance_type']})")
                        metrics = instance.get('metrics', {})
                        cols = st.columns(3)
                        cols[0].metric("CPU Avg", f"{metrics.get('CPUUtilization', {}).get('average', 0):.1f}%")
                        cols[1].metric("Network In", f"{metrics.get('NetworkIn', {}).get('average', 0)/1024/1024:.1f} MB")
                        cols[2].metric("Network Out", f"{metrics.get('NetworkOut', {}).get('average', 0)/1024/1024:.1f} MB")
                        
                        for rec in instance.get('recommendations', []):
                            sev_icon = {'HIGH': '🔴', 'MEDIUM': '🟡', 'LOW': '🟢', 'INFO': 'ℹ️'}.get(rec.get('severity'), '💡')
                            st.warning(f"{sev_icon} {rec['message']}: {rec['suggestion']}")
                        st.divider()
                else:
                    st.info("No running EC2 instances found")
            
            # API Gateway Analysis
            apigw_data = results.get('api_gateway', {})
            with st.expander(f"🌐 API Gateway ({apigw_data.get('total_apis', 0)} APIs)"):
                insights = apigw_data.get('insights', [])
                if insights:
                    for api in insights:
                        st.write(f"**{api['api_name']}** ({api['api_type']})")
                        metrics = api.get('metrics', {})
                        cols = st.columns(4)
                        cols[0].metric("Requests", f"{metrics.get('Count', {}).get('total', 0):,}")
                        cols[1].metric("Avg Latency", f"{metrics.get('Latency', {}).get('average', 0):.0f}ms")
                        cols[2].metric("4XX Errors", f"{metrics.get('4XXError', {}).get('total', 0):,}")
                        cols[3].metric("5XX Errors", f"{metrics.get('5XXError', {}).get('total', 0):,}")
                        
                        for rec in api.get('recommendations', []):
                            st.warning(f"💡 {rec['message']}: {rec['suggestion']}")
                        st.divider()
                else:
                    st.info("No API Gateway APIs found")
            
            # AI Recommendations
            st.divider()
            st.subheader("🤖 AI Performance Recommendations")
            if 'perf_ai_recs' in st.session_state and st.session_state['perf_ai_recs']:
                st.markdown(st.session_state['perf_ai_recs'])
        
        else:
            st.info("👆 Click 'Analyze Performance' to get insights on your AWS resources")
    
    except Exception as e:
        st.error(f"Error initializing Performance Analyzer: {str(e)}")

# ============================================
# 🏥 RESOURCE HEALTH TAB
# ============================================
elif selected_tab == "🏥 Health":
    st.header("🏥 Resource Health Dashboard")
    st.caption("Monitor health of EC2, RDS, Lambda, and CloudWatch Alarms")
    
    @st.cache_resource
    def init_health_dashboard():
        return AWSHealthDashboard()
    
    try:
        health_dashboard = init_health_dashboard()
        
        col1, col2 = st.columns([3, 1])
        with col2:
            run_check = st.button("🔍 Check Health", type="primary", use_container_width=True)
        
        if run_check:
            with st.spinner("Running health checks..."):
                results = health_dashboard.run_full_health_check()
                st.session_state['health_results'] = results
                
                ai_recs = health_dashboard.get_ai_recommendations(results)
                st.session_state['health_ai_recs'] = ai_recs
        
        if 'health_results' in st.session_state:
            results = st.session_state['health_results']
            scores = results.get('health_scores', {})
            overall = scores.get('overall', {})
            
            # Overall health score
            score = overall.get('score', 100)
            status = overall.get('status', 'UNKNOWN')
            
            if score >= 80:
                score_color = "🟢"
            elif score >= 60:
                score_color = "🟡"
            elif score >= 40:
                score_color = "🟠"
            else:
                score_color = "🔴"
            
            st.subheader(f"{score_color} Overall Health: {score}/100 ({status})")
            
            # Service health scores
            st.divider()
            cols = st.columns(4)
            
            ec2_score = scores.get('ec2', {})
            cols[0].metric("💻 EC2 Health", f"{ec2_score.get('score', 100)}%", 
                          delta=f"{ec2_score.get('healthy', 0)} healthy" if 'healthy' in ec2_score else None)
            
            rds_score = scores.get('rds', {})
            cols[1].metric("🗄️ RDS Health", f"{rds_score.get('score', 100)}%",
                          delta=f"{rds_score.get('available', 0)} available" if 'available' in rds_score else None)
            
            lambda_score = scores.get('lambda', {})
            cols[2].metric("⚡ Lambda Health", f"{lambda_score.get('score', 100)}%",
                          delta=f"{lambda_score.get('healthy', 0)} healthy" if 'healthy' in lambda_score else None)
            
            alarms_score = scores.get('cloudwatch_alarms', {})
            cols[3].metric("🔔 Alarms", f"{alarms_score.get('score', 100)}%",
                          delta=f"{alarms_score.get('alarm', 0)} in alarm" if 'alarm' in alarms_score else None,
                          delta_color="inverse")
            
            st.divider()
            
            # CloudWatch Alarms
            alarms_data = results.get('cloudwatch_alarms', {})
            alarms_summary = alarms_data.get('summary', {})
            with st.expander(f"🔔 CloudWatch Alarms ({alarms_data.get('total_alarms', 0)} total, {alarms_summary.get('ALARM', 0)} in alarm)", expanded=alarms_summary.get('ALARM', 0) > 0):
                alarms = alarms_data.get('alarms', [])
                if alarms:
                    for alarm in alarms[:20]:
                        state = alarm.get('state', 'UNKNOWN')
                        state_icon = {'ALARM': '🔴', 'OK': '🟢', 'INSUFFICIENT_DATA': '⚪'}.get(state, '❓')
                        st.markdown(f"{state_icon} **{alarm['name']}** - {alarm.get('metric_name', 'N/A')} ({alarm.get('namespace', 'N/A')})")
                        if state == 'ALARM':
                            st.caption(f"Reason: {alarm.get('state_reason', 'N/A')[:200]}")
                else:
                    st.info("No CloudWatch alarms configured")
            
            # EC2 Health
            ec2_data = results.get('ec2', {})
            with st.expander(f"💻 EC2 Instances ({ec2_data.get('total_instances', 0)} total)"):
                instances = ec2_data.get('instances', [])
                if instances:
                    for inst in instances:
                        health = inst.get('health', 'UNKNOWN')
                        health_icon = {'HEALTHY': '🟢', 'IMPAIRED': '🔴', 'INITIALIZING': '🟡', 'UNKNOWN': '⚪'}.get(health, '❓')
                        st.markdown(f"{health_icon} **{inst['instance_name']}** ({inst['instance_id']}) - {inst['instance_type']}")
                        if inst.get('events'):
                            for event in inst['events']:
                                st.warning(f"⚠️ Scheduled: {event.get('description')}")
                else:
                    st.info("No EC2 instances found")
            
            # RDS Health
            rds_data = results.get('rds', {})
            with st.expander(f"🗄️ RDS Instances ({rds_data.get('total_instances', 0)} total)"):
                instances = rds_data.get('instances', [])
                if instances:
                    for db in instances:
                        health = db.get('health', 'UNKNOWN')
                        health_icon = {'HEALTHY': '🟢', 'UNHEALTHY': '🔴', 'MAINTENANCE': '🟡', 'UNKNOWN': '⚪'}.get(health, '❓')
                        st.markdown(f"{health_icon} **{db['db_identifier']}** ({db['engine']}) - {db['status']}")
                        if db.get('pending_maintenance'):
                            st.warning(f"⚠️ Pending maintenance scheduled")
                else:
                    st.info("No RDS instances found")
            
            # Lambda Health
            lambda_data = results.get('lambda', {})
            with st.expander(f"⚡ Lambda Functions ({lambda_data.get('total_functions', 0)} total)"):
                functions = lambda_data.get('functions', [])
                if functions:
                    for func in functions[:20]:
                        health = func.get('health', 'UNKNOWN')
                        health_icon = {'HEALTHY': '🟢', 'DEGRADED': '🟡', 'UNHEALTHY': '🔴', 'INACTIVE': '⚪'}.get(health, '❓')
                        st.markdown(f"{health_icon} **{func['function_name']}** - {func['invocations']:,} invocations, {func['error_rate']}% errors")
                else:
                    st.info("No Lambda functions found")
            
            # AI Recommendations
            st.divider()
            st.subheader("🤖 AI Health Recommendations")
            if 'health_ai_recs' in st.session_state and st.session_state['health_ai_recs']:
                st.markdown(st.session_state['health_ai_recs'])
        
        else:
            st.info("👆 Click 'Check Health' to get the current health status of your AWS resources")
    
    except Exception as e:
        st.error(f"Error initializing Health Dashboard: {str(e)}")

# ============================================
# 📋 COMPLIANCE CHECKER TAB
# ============================================
elif selected_tab == "📋 Compliance":
    st.header("📋 Compliance & Best Practices")
    st.caption("Check against AWS Well-Architected Framework and best practices")
    
    @st.cache_resource
    def init_compliance_checker():
        return AWSComplianceChecker()
    
    try:
        compliance_checker = init_compliance_checker()
        
        col1, col2 = st.columns([3, 1])
        with col2:
            run_check = st.button("🔍 Run Compliance Check", type="primary", use_container_width=True)
        
        if run_check:
            with st.spinner("Running compliance checks..."):
                results = compliance_checker.run_full_compliance_check()
                st.session_state['compliance_results'] = results
                
                ai_recs = compliance_checker.get_ai_recommendations(results)
                st.session_state['compliance_ai_recs'] = ai_recs
        
        if 'compliance_results' in st.session_state:
            results = st.session_state['compliance_results']
            summary = results.get('summary', {})
            
            # Overall compliance score
            score = summary.get('overall_compliance_score', 100)
            if score >= 80:
                score_color = "🟢"
                status = "COMPLIANT"
            elif score >= 60:
                score_color = "🟡"
                status = "NEEDS IMPROVEMENT"
            else:
                score_color = "🔴"
                status = "NON-COMPLIANT"
            
            st.subheader(f"{score_color} Compliance Score: {score}/100 ({status})")
            
            # Severity breakdown
            severity = summary.get('severity_breakdown', {})
            cols = st.columns(5)
            cols[0].metric("🔴 Critical", severity.get('CRITICAL', 0))
            cols[1].metric("🟠 High", severity.get('HIGH', 0))
            cols[2].metric("🟡 Medium", severity.get('MEDIUM', 0))
            cols[3].metric("🟢 Low", severity.get('LOW', 0))
            cols[4].metric("📊 Total", summary.get('total_findings', 0))
            
            st.divider()
            
            # Well-Architected Pillar Scores
            st.subheader("🏛️ Well-Architected Framework Pillars")
            pillar_scores = summary.get('pillar_scores', {})
            
            pillar_names = {
                'operational_excellence': '⚙️ Operational Excellence',
                'security': '🔒 Security',
                'reliability': '🔄 Reliability',
                'performance_efficiency': '⚡ Performance Efficiency',
                'cost_optimization': '💰 Cost Optimization',
                'sustainability': '🌱 Sustainability'
            }
            
            cols = st.columns(3)
            for i, (key, name) in enumerate(pillar_names.items()):
                score = pillar_scores.get(key, 100)
                color = "🟢" if score >= 80 else "🟡" if score >= 60 else "🔴"
                cols[i % 3].metric(name, f"{color} {score}/100")
            
            st.divider()
            
            # Tagging Compliance
            tagging = results.get('tagging_compliance', {})
            tagging_summary = tagging.get('summary', {})
            with st.expander(f"🏷️ Tagging Compliance ({tagging_summary.get('compliance_rate', 0)}% compliant)"):
                st.metric("Compliance Rate", f"{tagging_summary.get('compliance_rate', 0)}%")
                cols = st.columns(2)
                cols[0].metric("Compliant Resources", tagging_summary.get('compliant', 0))
                cols[1].metric("Non-Compliant", tagging_summary.get('non_compliant', 0))
                
                required_tags = tagging.get('required_tags', [])
                st.caption(f"Required tags: {', '.join(required_tags)}")
                
                findings = tagging.get('findings', [])
                if findings:
                    st.subheader("Non-Compliant Resources")
                    for finding in findings[:10]:
                        st.warning(f"**{finding['resource_id']}** - Missing: {', '.join(finding.get('missing_tags', []))}")
            
            # Backup Policies
            backup = results.get('backup_policies', {})
            with st.expander(f"💾 Backup Policies ({backup.get('total_findings', 0)} issues)"):
                findings = backup.get('findings', [])
                if findings:
                    for finding in findings:
                        sev_icon = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}.get(finding.get('severity'), '⚪')
                        st.markdown(f"{sev_icon} **{finding['title']}**")
                        st.caption(finding.get('recommendation', ''))
                else:
                    st.success("✅ All backup policies are properly configured")
            
            # Multi-AZ
            multi_az = results.get('multi_az_deployments', {})
            with st.expander(f"🌍 Multi-AZ Deployments ({multi_az.get('total_findings', 0)} issues)"):
                findings = multi_az.get('findings', [])
                if findings:
                    for finding in findings:
                        sev_icon = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}.get(finding.get('severity'), '⚪')
                        st.markdown(f"{sev_icon} **{finding['resource_id']}**: {finding['title']}")
                        st.caption(finding.get('recommendation', ''))
                else:
                    st.success("✅ All critical resources are Multi-AZ enabled")
            
            # Logging & Monitoring
            logging_data = results.get('logging_monitoring', {})
            with st.expander(f"📊 Logging & Monitoring ({logging_data.get('total_findings', 0)} issues)"):
                findings = logging_data.get('findings', [])
                if findings:
                    for finding in findings:
                        sev_icon = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}.get(finding.get('severity'), '⚪')
                        st.markdown(f"{sev_icon} **{finding['resource_id']}**: {finding['title']}")
                        st.caption(finding.get('recommendation', ''))
                else:
                    st.success("✅ Logging and monitoring are properly configured")
            
            # AI Recommendations
            st.divider()
            st.subheader("🤖 AI Compliance Recommendations")
            if 'compliance_ai_recs' in st.session_state and st.session_state['compliance_ai_recs']:
                st.markdown(st.session_state['compliance_ai_recs'])
        
        else:
            st.info("👆 Click 'Run Compliance Check' to audit your AWS environment")
    
    except Exception as e:
        st.error(f"Error initializing Compliance Checker: {str(e)}")

# ============================================
# ⚠️ SERVICE QUOTA MONITOR TAB
# ============================================
elif selected_tab == "⚠️ Quotas":
    st.header("⚠️ Service Quota Monitor")
    st.caption("Track AWS service limits and usage to prevent hitting quotas")
    
    @st.cache_resource
    def init_quota_monitor():
        return AWSQuotaMonitor()
    
    try:
        quota_monitor = init_quota_monitor()
        
        col1, col2 = st.columns([3, 1])
        with col2:
            run_check = st.button("🔍 Check Quotas", type="primary", use_container_width=True)
        
        if run_check:
            with st.spinner("Checking service quotas and usage..."):
                results = quota_monitor.run_full_quota_check()
                st.session_state['quota_results'] = results
                
                ai_recs = quota_monitor.get_ai_recommendations(results)
                st.session_state['quota_ai_recs'] = ai_recs
        
        if 'quota_results' in st.session_state:
            results = st.session_state['quota_results']
            summary = results.get('summary', {})
            
            # Alert summary
            cols = st.columns(4)
            cols[0].metric("📊 Quotas Checked", summary.get('quotas_checked', 0))
            cols[1].metric("🔴 Critical Alerts", summary.get('critical_alerts', 0))
            cols[2].metric("🟡 Warning Alerts", summary.get('warning_alerts', 0))
            cols[3].metric("⚠️ Total Alerts", summary.get('total_alerts', 0))
            
            # Alerts section
            alerts = results.get('alerts', [])
            if alerts:
                st.divider()
                st.subheader("🚨 Quota Alerts")
                for alert in alerts:
                    sev_icon = '🔴' if alert['severity'] == 'CRITICAL' else '🟡'
                    st.warning(f"{sev_icon} **{alert['service']}**: {alert['quota']} at {alert['usage_percentage']}% usage")
            
            st.divider()
            
            # Quota details
            st.subheader("📊 Service Quotas")
            quotas = results.get('quotas', [])
            if quotas:
                for quota in quotas:
                    usage_pct = quota.get('usage_percentage', 0)
                    if usage_pct >= 90:
                        bar_color = "🔴"
                    elif usage_pct >= 70:
                        bar_color = "🟡"
                    else:
                        bar_color = "🟢"
                    
                    col1, col2, col3, col4 = st.columns([3, 1, 1, 1])
                    col1.write(f"**{quota.get('quota_name', 'Unknown')}**")
                    col2.write(f"{quota.get('current_usage', 0):.0f} / {quota.get('quota_value', 0):.0f}")
                    col3.write(f"{bar_color} {usage_pct}%")
                    col4.write("✅ Adjustable" if quota.get('adjustable') else "❌ Fixed")
                    
                    # Progress bar
                    st.progress(min(usage_pct / 100, 1.0))
            
            st.divider()
            
            # Usage summary by service
            st.subheader("📈 Resource Usage Summary")
            usage_summary = results.get('usage_summary', {})
            
            with st.expander("💻 EC2 Usage"):
                ec2 = usage_summary.get('ec2', {})
                if ec2:
                    cols = st.columns(4)
                    cols[0].metric("Running Instances", ec2.get('running_instances', 0))
                    cols[1].metric("Elastic IPs", ec2.get('elastic_ips', 0))
                    cols[2].metric("EBS Volumes", ec2.get('ebs_volumes', 0))
                    cols[3].metric("Snapshots", ec2.get('snapshots', 0))
            
            with st.expander("⚡ Lambda Usage"):
                lambda_usage = usage_summary.get('lambda', {})
                if lambda_usage:
                    cols = st.columns(3)
                    cols[0].metric("Functions", lambda_usage.get('function_count', 0))
                    cols[1].metric("Code Storage", f"{lambda_usage.get('total_code_size_mb', 0):.1f} MB")
                    cols[2].metric("Concurrent Limit", lambda_usage.get('concurrent_execution_limit', 0))
            
            with st.expander("🗄️ RDS Usage"):
                rds = usage_summary.get('rds', {})
                if rds:
                    cols = st.columns(4)
                    cols[0].metric("DB Instances", rds.get('db_instances', 0))
                    cols[1].metric("DB Clusters", rds.get('db_clusters', 0))
                    cols[2].metric("Total Storage", f"{rds.get('total_storage_gb', 0)} GB")
                    cols[3].metric("Manual Snapshots", rds.get('manual_snapshots', 0))
            
            with st.expander("👤 IAM Usage"):
                iam = usage_summary.get('iam', {})
                if iam:
                    cols = st.columns(4)
                    cols[0].metric("Users", f"{iam.get('users', 0)} / {iam.get('users_quota', 0)}")
                    cols[1].metric("Roles", f"{iam.get('roles', 0)} / {iam.get('roles_quota', 0)}")
                    cols[2].metric("Groups", f"{iam.get('groups', 0)} / {iam.get('groups_quota', 0)}")
                    cols[3].metric("Policies", f"{iam.get('policies', 0)} / {iam.get('policies_quota', 0)}")
            
            # AI Recommendations
            st.divider()
            st.subheader("🤖 AI Quota Recommendations")
            if 'quota_ai_recs' in st.session_state and st.session_state['quota_ai_recs']:
                st.markdown(st.session_state['quota_ai_recs'])
        
        else:
            st.info("👆 Click 'Check Quotas' to monitor your AWS service limits")
    
    except Exception as e:
        st.error(f"Error initializing Quota Monitor: {str(e)}")

# ============================================
# 🔄 BACKUP & DR TAB
# ============================================
elif selected_tab == "🔄 Backups":
    st.header("🔄 Backup & Disaster Recovery")
    st.caption("Monitor backup status, versioning, and DR readiness")
    
    @st.cache_resource
    def init_backup_analyzer():
        return AWSBackupAnalyzer()
    
    try:
        backup_analyzer = init_backup_analyzer()
        
        col1, col2 = st.columns([3, 1])
        with col2:
            run_check = st.button("🔍 Analyze Backups", type="primary", use_container_width=True)
        
        if run_check:
            with st.spinner("Analyzing backup and DR status..."):
                results = backup_analyzer.run_full_backup_analysis()
                st.session_state['backup_results'] = results
                
                ai_recs = backup_analyzer.get_ai_recommendations(results)
                st.session_state['backup_ai_recs'] = ai_recs
        
        if 'backup_results' in st.session_state:
            results = st.session_state['backup_results']
            dr_readiness = results.get('dr_readiness', {})
            
            # DR Readiness Score
            score = dr_readiness.get('score', 100)
            level = dr_readiness.get('readiness_level', 'UNKNOWN')
            
            if score >= 80:
                score_color = "🟢"
            elif score >= 60:
                score_color = "🟡"
            elif score >= 40:
                score_color = "🟠"
            else:
                score_color = "🔴"
            
            st.subheader(f"{score_color} DR Readiness Score: {score}/100 ({level})")
            
            # DR findings
            findings = dr_readiness.get('findings', [])
            if findings:
                st.warning("**Issues Affecting DR Readiness:**")
                for finding in findings:
                    st.markdown(f"- **{finding['category']}**: {finding['issue']} (-{finding['deduction']} points)")
            
            # Recommendations
            recommendations = dr_readiness.get('recommendations', [])
            if recommendations:
                st.info("**Recommendations:**")
                for rec in recommendations:
                    st.markdown(f"- {rec}")
            
            st.divider()
            
            # RDS Snapshots
            rds_data = results.get('rds_snapshots', {})
            rds_summary = rds_data.get('summary', {})
            with st.expander(f"🗄️ RDS Snapshots ({rds_summary.get('total_snapshots', 0)} total)"):
                cols = st.columns(4)
                cols[0].metric("Total Snapshots", rds_summary.get('total_snapshots', 0))
                cols[1].metric("Manual", rds_summary.get('manual_snapshots', 0))
                cols[2].metric("Automated", rds_summary.get('automated_snapshots', 0))
                cols[3].metric("Encrypted", rds_summary.get('encrypted_snapshots', 0))
                
                # Instances without backup
                without_backup = rds_data.get('instances_without_recent_backup', [])
                if without_backup:
                    st.warning(f"⚠️ {len(without_backup)} database(s) without recent backup:")
                    for db in without_backup:
                        st.markdown(f"- **{db['db_identifier']}** - Last backup: {db.get('latest_backup_age_days', 'Never')} days ago")
                
                # Recent snapshots
                snapshots = rds_data.get('snapshots', [])[:10]
                if snapshots:
                    st.subheader("Recent Snapshots")
                    for snap in snapshots:
                        enc_icon = "🔒" if snap.get('encrypted') else "🔓"
                        st.markdown(f"{enc_icon} **{snap['snapshot_id']}** ({snap['db_instance']}) - {snap['age_days']} days old, {snap['allocated_storage_gb']} GB")
            
            # S3 Versioning
            s3_data = results.get('s3_versioning', {})
            s3_summary = s3_data.get('summary', {})
            with st.expander(f"🪣 S3 Buckets ({s3_summary.get('total_buckets', 0)} total)"):
                cols = st.columns(4)
                cols[0].metric("Total Buckets", s3_summary.get('total_buckets', 0))
                cols[1].metric("Versioning Enabled", s3_summary.get('versioning_enabled', 0))
                cols[2].metric("With Lifecycle Rules", s3_summary.get('with_lifecycle_rules', 0))
                cols[3].metric("With Replication", s3_summary.get('with_replication', 0))
                
                # Bucket details
                buckets = s3_data.get('buckets', [])
                for bucket in buckets[:15]:
                    ver_icon = "✅" if bucket['versioning'] == 'Enabled' else "❌"
                    rep_icon = "🔄" if bucket['replication'] else ""
                    st.markdown(f"{ver_icon} **{bucket['bucket_name']}** - Versioning: {bucket['versioning']}, Lifecycle Rules: {bucket['lifecycle_rules']} {rep_icon}")
            
            # Cross-Region Replication
            crr_data = results.get('cross_region_replication', {})
            crr_summary = crr_data.get('summary', {})
            with st.expander(f"🌍 Cross-Region Replication ({sum(crr_summary.values())} configs)"):
                configs = crr_data.get('replication_configs', [])
                if configs:
                    for config in configs:
                        st.markdown(f"**{config['type']}**: {config.get('source', config.get('table_name', 'N/A'))} → {config.get('destination', config.get('replica_region', 'N/A'))}")
                else:
                    st.info("No cross-region replication configured")
            
            # EC2 Backups
            ec2_data = results.get('ec2_backups', {})
            ec2_summary = ec2_data.get('summary', {})
            with st.expander(f"💻 EC2 AMIs & Snapshots ({ec2_summary.get('total_amis', 0)} AMIs, {ec2_summary.get('total_snapshots', 0)} snapshots)"):
                cols = st.columns(4)
                cols[0].metric("Total AMIs", ec2_summary.get('total_amis', 0))
                cols[1].metric("Old AMIs (>90d)", ec2_summary.get('old_amis_90_days', 0))
                cols[2].metric("Total Snapshots", ec2_summary.get('total_snapshots', 0))
                cols[3].metric("Snapshot Storage", f"{ec2_summary.get('total_snapshot_storage_gb', 0)} GB")
                
                without_ami = ec2_data.get('instances_without_ami', [])
                if without_ami:
                    st.warning(f"⚠️ {len(without_ami)} critical instance(s) without AMI backup:")
                    for inst in without_ami:
                        st.markdown(f"- **{inst['instance_name']}** ({inst['instance_id']})")
            
            # AWS Backup
            aws_backup = results.get('aws_backup', {})
            backup_summary = aws_backup.get('summary', {})
            with st.expander(f"☁️ AWS Backup ({backup_summary.get('total_plans', 0)} plans, {backup_summary.get('total_protected_resources', 0)} protected resources)"):
                cols = st.columns(4)
                cols[0].metric("Backup Vaults", backup_summary.get('total_vaults', 0))
                cols[1].metric("Backup Plans", backup_summary.get('total_plans', 0))
                cols[2].metric("Protected Resources", backup_summary.get('total_protected_resources', 0))
                cols[3].metric("Recovery Points", backup_summary.get('total_recovery_points', 0))
                
                plans = aws_backup.get('plans', [])
                if plans:
                    st.subheader("Backup Plans")
                    for plan in plans:
                        st.markdown(f"**{plan.get('plan_name', 'Unnamed')}** - {plan.get('rules_count', 0)} rules")
            
            # AI Recommendations
            st.divider()
            st.subheader("🤖 AI Backup & DR Recommendations")
            if 'backup_ai_recs' in st.session_state and st.session_state['backup_ai_recs']:
                st.markdown(st.session_state['backup_ai_recs'])
        
        else:
            st.info("👆 Click 'Analyze Backups' to check your backup and DR status")
    
    except Exception as e:
        st.error(f"Error initializing Backup Analyzer: {str(e)}")

elif selected_tab == "📜 Incident History":
    st.header("📜 Full Incident History")
    
    # Extended filters
    col1, col2, col3 = st.columns(3)
    with col1:
        history_hours = st.selectbox(
            "Time Range", 
            [24, 48, 72, 168, 336], 
            format_func=lambda x: f"{x} hours ({x//24} days)" if x >= 24 else f"{x} hours",
            key="history_hours"
        )
    with col2:
        history_severity = st.selectbox(
            "Severity", 
            ["All", "CRITICAL", "WARNING", "INFO"], 
            key="history_severity"
        )
    
    history_incidents = db.get_recent_incidents(
        hours=history_hours,
        severity=None if history_severity == "All" else history_severity
    )
    
    if history_incidents:
        # Convert to display format
        display_data = []
        for inc in history_incidents:
            display_data.append({
                "Time": inc['timestamp'],
                "Severity": inc['severity'],
                "Summary": inc['summary'],
                "Log Group": inc['log_group'],
                "Service": inc['affected_service'],
                "Resolved": "✓" if inc['resolved'] else "✗"
            })
        
        st.dataframe(
            display_data,
            column_config={
                "Time": st.column_config.DatetimeColumn("Time", format="YYYY-MM-DD HH:mm"),
                "Severity": st.column_config.TextColumn("Severity", width="small"),
                "Summary": st.column_config.TextColumn("Summary", width="large"),
                "Log Group": st.column_config.TextColumn("Log Group", width="medium"),
                "Service": st.column_config.TextColumn("Service", width="small"),
                "Resolved": st.column_config.TextColumn("Resolved", width="small")
            },
            hide_index=True,
            width='stretch'
        )
        
        st.caption(f"Showing {len(history_incidents)} incidents")
    else:
        st.info("No incidents found for selected filters")

elif selected_tab == "📋 Raw Logs":
    st.header("📋 Live Logs Viewer")
    st.caption("Log tailing for your Lambda functions")
    
    # Control panel - Full width for log group selector
    if 'log_groups' in st.session_state and st.session_state['log_groups']:
        # Initialize viewer_log_group in session state if not exists
        if 'viewer_log_group' not in st.session_state:
            st.session_state['viewer_log_group'] = st.session_state['log_groups'][0]
        
        # Find current index
        current_idx = 0
        try:
            current_idx = st.session_state['log_groups'].index(st.session_state['viewer_log_group'])
        except (ValueError, AttributeError):
            current_idx = 0
        
        viewer_log_group = st.selectbox(
            "Select Log Group",
            options=st.session_state['log_groups'],
            index=current_idx,
            key="viewer_log_group_select",
            help="Full path of the CloudWatch log group",
            on_change=lambda: st.session_state.update({'viewer_log_group': st.session_state['viewer_log_group_select']})
        )
        # Update the stored selection
        st.session_state['viewer_log_group'] = viewer_log_group
    else:
        viewer_log_group = st.text_input(
            "Log Group",
            value=st.session_state.get('viewer_log_group', "/aws/lambda/my-function"),
            key="viewer_log_group_input",
            help="💡 Click 'Discover Log Groups' in the sidebar to select from a list"
        )
        st.session_state['viewer_log_group'] = viewer_log_group
    
    # Options row
    col1, col2, col3, col4 = st.columns([2, 1, 1, 1])
    with col1:
        # Search filter
        search_text = st.text_input(
            "🔍 Filter logs",
            placeholder="Search for errors, keywords, etc...",
            key="log_search"
        )
    
    with col2:
        # Bref-style "since" selector
        since_options = {
            "5m": 5,
            "15m": 15,
            "30m": 30,
            "1h": 60,
            "3h": 180,
            "6h": 360,
            "12h": 720,
            "24h": 1440,
            "All": 10080
        }
        since_choice = st.selectbox(
            "Since",
            options=list(since_options.keys()),
            index=8,  # Default to All
            key="since_choice"
        )
        viewer_minutes = since_options[since_choice]
    
    with col3:
        viewer_limit = st.number_input(
            "Max Logs",
            min_value=10,
            max_value=1000,
            value=100,
            step=50,
            key="viewer_limit"
        )
    
    with col4:
        tail_mode = st.checkbox("🔥 Tail", value=False, help="Auto-refresh every 5 seconds")
    
    # Level filter
    log_level_filter = st.selectbox(
        "Log Level Filter",
        options=["All", "Errors Only", "Warnings+", "Info+"],
        key="log_level"
    )
    
    # Tail mode auto-refresh
    if tail_mode:
        import time
        if 'last_tail_refresh' not in st.session_state:
            st.session_state['last_tail_refresh'] = time.time()
        
        # Refresh every 5 seconds in tail mode
        if time.time() - st.session_state['last_tail_refresh'] > 5:
            st.session_state['last_tail_refresh'] = time.time()
            st.rerun()
        
        st.info("🔥 **Tail mode active** - Auto-refreshing every 5 seconds ")
    
    # Initialize load more counter
    if 'log_load_count' not in st.session_state:
        st.session_state['log_load_count'] = 1
    
    # Calculate actual limit with load more
    actual_limit = viewer_limit * st.session_state['log_load_count']
    
    # Fetch logs
    if viewer_log_group:
        viewer_placeholder = st.empty()
        with viewer_placeholder.container():
            show_loading_spinner(f"📡 Fetching logs from {viewer_log_group}...")
        logs = collector.fetch_recent_logs(
            log_group_name=viewer_log_group,
            minutes=viewer_minutes,
            limit=actual_limit,
            filter_text=search_text if search_text else None
        )
        viewer_placeholder.empty()
        
        # Apply log level filter
        if log_level_filter != "All" and logs:
            if log_level_filter == "Errors Only":
                logs = [l for l in logs if any(kw in l['message'].lower() for kw in ['error', 'exception', 'fatal', 'critical'])]
            elif log_level_filter == "Warnings+":
                logs = [l for l in logs if any(kw in l['message'].lower() for kw in ['error', 'exception', 'fatal', 'critical', 'warn', 'warning'])]
        
        if not logs:
            time_display = since_choice if since_choice != "All" else "available time period"
            st.info(f"📭 No logs found in the last {time_display}")
        else:
            # Header with stats
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("📊 Log Entries", len(logs))
            with col2:
                error_count = sum(1 for l in logs if any(kw in l['message'].lower() for kw in ['error', 'exception', 'fatal']))
                st.metric("🔴 Errors", error_count)
            with col3:
                if logs:
                    latest_log_time = logs[0]['timestamp']
                    time_ago = (datetime.now() - latest_log_time).total_seconds()
                    if time_ago < 60:
                        time_str = f"{int(time_ago)}s ago"
                    elif time_ago < 3600:
                        time_str = f"{int(time_ago/60)}m ago"
                    else:
                        time_str = f"{int(time_ago/3600)}h ago"
                    st.metric("🕐 Latest", time_str)
            
            st.divider()
            
            # Display logs in Bref-style format (all visible at once)
            st.markdown("---")
            
            # Container for all logs
            log_display = []
            for i, log_entry in enumerate(logs):
                timestamp_str = log_entry['timestamp'].strftime("%H:%M:%S")
                full_timestamp = log_entry['timestamp'].strftime("%Y-%m-%d %H:%M:%S")
                stream = log_entry['stream'].split('/')[-1]  # Show only stream ID
                message = log_entry['message'].strip()
                
                # Determine log level with theme-aware colors
                is_dark = st.session_state.get('theme', 'dark') == 'dark'
                
                if any(keyword in message.lower() for keyword in ['error', 'exception', 'fatal', 'critical']):
                    level_icon = "🔴"
                    level_text = "ERROR"
                    bg_color = "#3d1a1a" if is_dark else "#ffe6e6"
                    border_color = "#ff4444"
                    text_color = "#eee" if is_dark else "#333"
                elif any(keyword in message.lower() for keyword in ['warn', 'warning']):
                    level_icon = "🟡"
                    level_text = "WARN"
                    bg_color = "#3d2e1a" if is_dark else "#fff8e6"
                    border_color = "#ffaa00"
                    text_color = "#eee" if is_dark else "#333"
                else:
                    level_icon = "🟢"
                    level_text = "INFO"
                    bg_color = "#1a2d1a" if is_dark else "#e6ffe6"
                    border_color = "#44ff44"
                    text_color = "#eee" if is_dark else "#333"
                
                # Build log entry HTML
                log_display.append(f"""
                <div style='
                    font-family: "Courier New", monospace; 
                    font-size: 13px; 
                    padding: 10px; 
                    margin-bottom: 5px; 
                    background-color: {bg_color}; 
                    border-left: 4px solid {border_color};
                    border-radius: 3px;
                '>
                    <div style='margin-bottom: 5px;'>
                        <span style='color: #888;'>{full_timestamp}</span> 
                        <span style='color: #0af;'>[{stream[:30]}]</span> 
                        <span style='color: {border_color}; font-weight: bold;'>{level_icon} {level_text}</span>
                    </div>
                    <div style='color: {text_color}; white-space: pre-wrap; font-size: 12px;'>{message}</div>
                </div>
                """)
            
            # Display all logs at once
            st.markdown("".join(log_display), unsafe_allow_html=True)
            
            st.divider()
            
            # Load More button
            col1, col2, col3 = st.columns([1, 2, 1])
            with col2:
                if actual_limit < 1000:  # Max limit
                    if st.button("📥 Load More Logs", width='stretch', type="secondary"):
                        st.session_state['log_load_count'] += 1
                        st.rerun()
                    st.caption(f"Currently showing {len(logs)} logs • Click to load {viewer_limit} more")
                else:
                    st.caption(f"Showing {len(logs)} logs (maximum reached)")
            
            st.divider()
            st.caption(f"💡 Loaded {st.session_state['log_load_count']}x batches ({len(logs)} total logs from last {since_choice}) • {'🔥 Tail mode active' if tail_mode else '✓ Static view'}")
            
            # Reset button
            if st.session_state['log_load_count'] > 1:
                if st.button("🔄 Reset to default view"):
                    st.session_state['log_load_count'] = 1
                    st.rerun()
            
            # Laravel log info
            if any('laravel' in lg.lower() for lg in [viewer_log_group]):
                st.info("ℹ️ **Laravel Logs**: Laravel log entries from `storage/logs/laravel.log` are automatically captured by Bref and sent to CloudWatch. You're viewing them here!")
    else:
        st.info("👆 Select a log group to start viewing logs")

elif selected_tab == "⚙️ Settings":
    st.header("⚙️ System Settings")
    
    # Noise patterns management
    st.subheader("🔇 Noise Patterns")
    st.caption("Patterns that will be automatically filtered out during analysis")
    
    patterns = db.get_noise_patterns_detailed()
    if patterns:
        import pandas as pd
        
        # Format patterns for display
        display_data = []
        for p in patterns:
            display_data.append({
                "Pattern": p['pattern'],
                "Log Group": p['log_group'] or "Global",
                "Description": p['description'] or "-",
                "Created": p['created_at'].strftime("%Y-%m-%d") if p['created_at'] else "-"
            })
        
        st.dataframe(
            pd.DataFrame(display_data),
            hide_index=True,
            width='stretch',
            column_config={
                "Pattern": st.column_config.TextColumn("Pattern", width="large"),
                "Log Group": st.column_config.TextColumn("Log Group", width="medium"),
                "Description": st.column_config.TextColumn("Description", width="medium")
            }
        )
    else:
        st.info("No noise patterns configured")
    
    # Add new pattern
    with st.form("add_pattern"):
        st.subheader("Add New Pattern")
        new_pattern = st.text_input("Pattern", placeholder="e.g., Connection reset by peer")
        
        # Log group selection for pattern
        available_groups = ["Global (All Log Groups)"]
        if 'log_groups' in st.session_state:
            available_groups.extend(st.session_state['log_groups'])
        
        pattern_log_group = st.selectbox(
            "Apply to Log Group",
            options=available_groups,
            index=0,
            help="Choose 'Global' to apply this filter everywhere, or select a specific log group"
        )
        
        new_description = st.text_input("Description (optional)", placeholder="Why this should be ignored")
        
        if st.form_submit_button("➕ Add Pattern"):
            if new_pattern:
                # Convert 'Global' back to None
                actual_log_group = None if pattern_log_group == "Global (All Log Groups)" else pattern_log_group
                
                if db.add_noise_pattern(new_pattern, actual_log_group, new_description):
                    st.success(f"Added pattern: {new_pattern}")
                    st.rerun()
                else:
                    st.error("Failed to add pattern")
            else:
                st.warning("Please enter a pattern")
    
    st.divider()
    
    # System info
    st.subheader("📊 System Information")
    
    col1, col2 = st.columns(2)
    with col1:
        st.metric("MySQL Host", os.getenv('MYSQL_HOST', 'localhost'))
        st.metric("MySQL Database", os.getenv('MYSQL_DATABASE', 'cloudwatch_sentinel'))
    
    with col2:
        st.metric("AWS Region", os.getenv('AWS_DEFAULT_REGION', 'us-east-1'))
        st.metric("OpenAI Model", os.getenv('OPENAI_MODEL', 'gpt-4o-mini'))
    
    st.divider()
    
    # Danger zone
    st.subheader("🗑️ Maintenance")
    
    col1, col2 = st.columns(2)
    with col1:
        cleanup_days = st.number_input("Delete incidents older than (days)", min_value=7, max_value=365, value=90)
    
    with col2:
        if st.button("🗑️ Run Cleanup", type="secondary"):
            deleted = db.delete_old_incidents(cleanup_days)
            st.success(f"Deleted {deleted} old incidents")
