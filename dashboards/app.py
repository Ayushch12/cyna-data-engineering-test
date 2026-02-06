
"""
SOC Security Dashboard – Analyst View
Professional, explainable SOC-style dashboard
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(PROJECT_ROOT))

import streamlit as st
import pandas as pd
import plotly.express as px
from storage.duckdb_setup import get_connection
# Page config
st.set_page_config(
    page_title="SOC Security Dashboard",
    layout="wide",
)
# SOC styling (neutral, professional)
st.markdown(
    """
    <style>
    body {
        background-color: #020617;
        color: #e5e7eb;
    }

.kpi-card {
    background: linear-gradient(
        135deg,
        #e5e7eb 0%,
        #f3f4f6 35%,
        #e5e7eb 65%,
        #d1d5db 100%
    );
    border: 1px solid #d1d5db;
    border-radius: 14px;
    padding: 22px;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
}


    .kpi-label {

        font-size: 20px;
        letter-spacing: 1px;
        text-transform: uppercase;
    }

    .kpi-value {

        font-size: 36px;
        font-weight: 700;
        margin-top: 6px;
    }

    /* ---- FIX FILTER TAG COLORS (NO RED) ---- */
    span[data-baseweb="tag"] {
       background: linear-gradient(
    135deg,
    #d1d5db,
    #e5e7eb,
    #d1d5db
) !important;

        color: #111827 !important;


        border-radius: 6px !important;
        font-size: 15px;
    }

    span[data-baseweb="tag"] svg {
        fill: #9ca3af !important;
    }

    span[data-baseweb="tag"]:hover {

    }

    hr {
        border: none;
        border-top: 1px solid #1e293b;
        margin: 30px 0;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# Data loading

# @st.cache_data
def load_data():
    conn = get_connection()
    df = conn.execute("SELECT * FROM enriched_logs").fetchdf()
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df


df = load_data()

if df.empty:
    st.error("No data available")
    st.stop()

# Sidebar filters
st.sidebar.header("Filters")

date_min = df["timestamp"].min().date()
date_max = df["timestamp"].max().date()

date_range = st.sidebar.date_input(
    "Date range",
    min_value=date_min,
    max_value=date_max,
    value=(date_min, date_max),
)

severity_filter = st.sidebar.multiselect(
    "Severity",
    options=sorted(df["severity"].unique()),
    default=sorted(df["severity"].unique()),
)

protocol_filter = st.sidebar.multiselect(
    "Protocol",
    options=sorted(df["protocol"].unique()),
    default=sorted(df["protocol"].unique()),
)

filtered_df = df[
    (df["timestamp"].dt.date >= date_range[0]) &
    (df["timestamp"].dt.date <= date_range[1]) &
    (df["severity"].isin(severity_filter)) &
    (df["protocol"].isin(protocol_filter))
]


# Header
st.title("🛡️ SOC Security Dashboard")
st.caption("Operational visibility from IDS logs enriched with threat intelligence")

# KPI CARDS
total_events = len(filtered_df)
malicious_events = int(filtered_df["is_malicious"].sum())
benign_events = total_events - malicious_events

c1, c2, c3 = st.columns(3)

with c1:
    st.markdown(
        f"""
        <div class="kpi-card">
            <div class="kpi-label">Total Events</div>
            <div class="kpi-value">{total_events}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with c2:
    st.markdown(
        f"""
        <div class="kpi-card">
            <div class="kpi-label">Malicious Events</div>
            <div class="kpi-value">{malicious_events}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with c3:
    st.markdown(
        f"""
        <div class="kpi-card">
            <div class="kpi-label">Benign Events</div>
            <div class="kpi-value">{benign_events}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

st.markdown("<hr>", unsafe_allow_html=True)

# Severity Distribution
st.subheader(" Severity Distribution")

severity_df = (
    filtered_df.groupby("severity")
    .size()
    .reset_index(name="count")
    .sort_values("count")
)

sev_fig = px.bar(
    severity_df,
    x="severity",
    y="count",
    template="plotly_dark",
    color_discrete_sequence=["#60a5fa"],
)

sev_fig.update_layout(yaxis_title="Events")
st.plotly_chart(sev_fig, use_container_width=True)

# Protocol Distribution
st.subheader(" Protocol Usage")

proto_df = (
    filtered_df.groupby("protocol")
    .size()
    .reset_index(name="count")
    .sort_values("count")
)

proto_fig = px.bar(
    proto_df,
    x="protocol",
    y="count",
    template="plotly_dark",
    color_discrete_sequence=["#38bdf8"],
)

proto_fig.update_layout(yaxis_title="Events")
st.plotly_chart(proto_fig, use_container_width=True)

# Event Timeline
st.subheader(" Event Timeline")

filtered_df["event_day"] = filtered_df["timestamp"].dt.floor("D")

timeline_df = (
    filtered_df.groupby("event_day")
    .size()
    .reset_index(name="count")
)

timeline_fig = px.line(
    timeline_df,
    x="event_day",
    y="count",
    template="plotly_dark",
)

timeline_fig.update_traces(line_color="#22c55e")
timeline_fig.update_layout(yaxis_title="Events")

st.plotly_chart(timeline_fig, use_container_width=True)

#Top Destination Assets
st.subheader("Top Destination Assets")

# 1️⃣ Build the data
top_dst_df = (
    filtered_df
    .groupby("dst_ip")
    .size()
    .reset_index(name="event_count")
    .sort_values("event_count", ascending=False)
    .head(10)
)

# 2️⃣ Show the bar chart (prioritization)
dst_fig = px.bar(
    top_dst_df,
    x="event_count",
    y="dst_ip",
    orientation="h",
    template="plotly_dark",
    text="event_count",
)

dst_fig.update_traces(
    marker_color="#60a5fa",
    textposition="outside"
)

dst_fig.update_layout(
    xaxis_title="Number of Events",
    yaxis_title="Destination IP",
    yaxis=dict(autorange="reversed"),
    margin=dict(l=140, r=40, t=40, b=40),
)

st.plotly_chart(dst_fig, use_container_width=True)

# Top Malicious IPs (SOC-style table)
st.subheader("Top Malicious Source IPs")

top_ips = (
    filtered_df[filtered_df["is_malicious"] == True]
    .groupby("src_ip")
    .size()
    .reset_index(name="Event Count")
    .sort_values("Event Count", ascending=False)
    .head(10)
)

if top_ips.empty:
    st.info("No malicious IPs detected")
else:
    top_ips.insert(0, "Rank", range(1, len(top_ips) + 1))
    top_ips = top_ips.rename(columns={"src_ip": "Source IP"})

    table_html = f"""
    <div style="
        background: linear-gradient(
            135deg,
            #e5e7eb 0%,
            #f3f4f6 35%,
            #e5e7eb 65%,
            #d1d5db 100%
        );
        border: 1px solid #d1d5db;
        border-radius: 14px;
        padding: 16px;
    ">
        <table style="width:100%; border-collapse: collapse;">
            <thead>
                <tr>
                    {''.join([
                        f"<th style='font-size:20px; text-align:left; padding:10px;'>{col}</th>"
                        for col in top_ips.columns
                    ])}
                </tr>
            </thead>
            <tbody>
                {''.join([
                    "<tr>" + "".join([
                        f"<td style='padding:10px; font-size:16px;'>{val}</td>"
                        for val in row
                    ]) + "</tr>"
                    for row in top_ips.values
                ])}
            </tbody>
        </table>
    </div>
    """

    st.markdown(table_html, unsafe_allow_html=True)

# Confidence Heatmap
st.subheader("Threat Confidence Heatmap")

heatmap_df = (
    filtered_df[filtered_df["is_malicious"] == True]
    .groupby(["severity", "confidence_level"])
    .size()
    .reset_index(name="count")
)

if heatmap_df.empty:
    st.info("No data for confidence heatmap")
else:
    heatmap_fig = px.density_heatmap(
        heatmap_df,
        x="confidence_level",
        y="severity",
        z="count",
        template="plotly_dark",
        color_continuous_scale="Reds",
    )
    st.plotly_chart(heatmap_fig, use_container_width=True)

# Malicious Event Details
st.subheader("Malicious Event Details")

malicious_df = filtered_df[filtered_df["is_malicious"] == True]

if malicious_df.empty:
    st.info("No malicious events detected")
else:
    display_df = malicious_df[
        [
            "timestamp",
            "severity",
            "protocol",
            "src_ip",
            "dst_ip",
            "confidence_level",
            "message",
        ]
    ].copy()

    display_df.columns = [
        "Timestamp",
        "Severity",
        "Protocol",
        "Source IP",
        "Destination IP",
        "Confidence",
        "Message",
    ]

    table_html = f"""
    <div style="
        background: linear-gradient(
            135deg,
            #e5e7eb 0%,
            #f3f4f6 35%,
            #e5e7eb 65%,
            #d1d5db 100%
        );
        border: 1px solid #d1d5db;
        border-radius: 14px;
        padding: 16px;
        overflow-x: auto;
    ">
        <table style="width:100%; border-collapse: collapse;">
            <thead>
                <tr>
                    {''.join([
                        f"<th style='font-size:20px; text-align:left; padding:10px;'>{col}</th>"
                        for col in display_df.columns
                    ])}
                </tr>
            </thead>
            <tbody>
                {''.join([
                    "<tr>" + "".join([
                        f"<td style='padding:10px; font-size:15px;'>{val}</td>"
                        for val in row
                    ]) + "</tr>"
                    for row in display_df.values
                ])}
            </tbody>
        </table>
    </div>
    """

    st.markdown(table_html, unsafe_allow_html=True)

st.markdown("<hr>", unsafe_allow_html=True)



st.caption("SOC Dashboard • Built for operational security analysis")
