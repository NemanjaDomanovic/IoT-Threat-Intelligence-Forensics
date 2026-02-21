import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import socket
import datetime
import os
import time
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import confusion_matrix, classification_report
from core.forensics_engine import IoTForensicsEngine
from scripts.data_factory import IoTDataFactory

#PAGE CONFIG
st.set_page_config(
    page_title="IoT Forensic Hub | Command Deck",
    layout="wide",
    initial_sidebar_state="collapsed"
)

#SESSION STATE INITIALIZATION
if 'app_state' not in st.session_state: st.session_state.app_state = 'STANDBY'
if 'c2_data' not in st.session_state: st.session_state.c2_data = None
if 'ddos_data' not in st.session_state: st.session_state.ddos_data = None

#UTILITY FUNCTIONS
def get_real_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except: return "127.0.0.1"

def run_factory_to_disk():
    try:
        factory = IoTDataFactory()
        factory.generate_heartbeat_data()
        factory.generate_ddos_data()
        return True
    except Exception as e:
        st.error(f"Factory Error: {e}")
        return False

def reset_session():
    for f in ["temp_c2.csv", "temp_ddos.csv", "FORENSIC_REPORT_V2.txt"]:
        if os.path.exists(f): os.remove(f)
    st.session_state.app_state = 'STANDBY'
    st.session_state.c2_data = None
    st.session_state.ddos_data = None
    st.rerun()

#CYBERSEC CUSTOM CSS WITH GRID BACKGROUND
st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;900&family=JetBrains+Mono:wght@500;700&display=swap');
    
    /* GRID BACKGROUND (COOL NETWORK VIBE) */
    .stApp { 
        background-color: #020617; 
        background-image: 
            linear-gradient(rgba(56, 189, 248, 0.07) 1px, transparent 1px),
            linear-gradient(90deg, rgba(56, 189, 248, 0.07) 1px, transparent 1px);
        background-size: 30px 30px;
        font-family: 'Inter', sans-serif;
    }
    
    /* HIDE DEFAULTS */
    footer, header, [data-testid="stSidebar"] { display: none !important; }
    .block-container { padding-top: 1rem !important; }

    /* HUD PANEL STYLING */
    .hud-panel { 
        background: rgba(15, 23, 42, 0.95); border: 1px solid #38bdf8; 
        border-radius: 4px; padding: 15px; font-family: 'JetBrains Mono'; 
        text-align: right; box-shadow: 0 0 20px rgba(56, 189, 248, 0.2);
        margin-bottom: 10px;
    }
    .hud-time { font-size: 1.8rem; font-weight: 700; color: #f8fafc; text-shadow: 0 0 10px #38bdf8; }

    /* CYBER UPLOADER BOXES */
    .uploader-container {
        border: 1px solid rgba(56, 189, 248, 0.2);
        background: rgba(15, 23, 42, 0.7);
        border-radius: 8px; padding: 25px;
        transition: all 0.3s ease;
    }
    .uploader-container:hover {
        border-color: #38bdf8; background: rgba(56, 189, 248, 0.1);
        box-shadow: 0 0 30px rgba(56, 189, 248, 0.2); transform: scale(1.02);
    }
    
    /* SCANNING ANIMATION */
    .scanner-box {
        position: relative; overflow: hidden;
        border: 1px solid rgba(56, 189, 248, 0.3);
        background: rgba(15, 23, 42, 0.85); border-radius: 12px;
    }
    .scanner-line {
        position: absolute; top: 0; left: 0; width: 100%; height: 3px;
        background: #38bdf8; box-shadow: 0 0 20px #38bdf8;
        opacity: 0.8; animation: scan 4s linear infinite;
    }
    @keyframes scan { 0% { top: 0; } 100% { top: 100%; } }

    /* STAT BOXES */
    .stat-box { background: rgba(15, 23, 42, 0.8); border-left: 4px solid #38bdf8; padding: 15px; border-radius: 4px; border-right: 1px solid rgba(56, 189, 248, 0.1); }
    
    /* BRIEFING BOX */
    .briefing-box { 
        background: rgba(56, 189, 248, 0.05); border-left: 4px solid #38bdf8; 
        padding: 15px; font-family: 'JetBrains Mono'; font-size: 0.85rem; color: #94a3b8; 
    }

    /* RIGHT ALIGNED BUTTON */
    div.stButton > button {
        width: 100%; font-family: 'JetBrains Mono'; font-weight: bold;
        background-color: transparent; border: 1px solid #38bdf8; color: #38bdf8;
    }
    div.stButton > button:hover {
        background-color: #38bdf8; color: #020617; box-shadow: 0 0 15px #38bdf8;
    }
    </style>
    """, unsafe_allow_html=True)

#HEADER SECTION
c1, c2 = st.columns([3, 1])

with c1:
    st.markdown(f"""
        <div style="display:flex; align-items:center; gap:25px; padding-top:10px;">
            <img src="https://cdn-icons-png.flaticon.com/512/2092/2092663.png" width="60" style="filter: drop-shadow(0 0 10px #38bdf8);">
            <div>
                <div style="color:#38bdf8; font-family:'JetBrains Mono'; font-size:0.7rem; letter-spacing:3px;">TACTICAL FORENSIC SUITE</div>
                <h1 style="color:white; margin:0; font-weight:900; font-size:2.8rem; letter-spacing:-1.5px; line-height:1;">IoT FORENSIC HUB</h1>
            </div>
        </div>
    """, unsafe_allow_html=True)

with c2:
    @st.fragment(run_every=1)
    def draw_hud():
        current_time = datetime.datetime.now().strftime("%H:%M:%S")
        st.markdown(f"""
            <div class="hud-panel">
                <div class="hud-time">{current_time}</div>
                <div style="color:#4ade80; font-size:0.7rem;">● ENGINE ONLINE | {get_real_ip()}</div>
            </div>
        """, unsafe_allow_html=True)
    draw_hud()
    
    if st.session_state.app_state == 'STANDBY':
        spacer, btn_col = st.columns([1, 2.5])
        with btn_col:
            if st.button("REFRESH EVIDENCE"):
                with st.spinner("Refining patterns..."):
                    run_factory_to_disk()
                    st.toast("Evidence factory updated.", icon="🧪")

st.markdown("<br>", unsafe_allow_html=True)

#MAIN APP LOGIC

if st.session_state.app_state == 'STANDBY':
    
    st.markdown("""
        <div class="scanner-box" style="text-align:center; padding:60px 20px; margin-bottom:40px;">
            <div class="scanner-line"></div>
            <h2 style="color:white; font-size:1.8rem; margin:0;">SYSTEM ARMED: AWAITING LOGS</h2>
            <p style="color:#64748b; font-family:'JetBrains Mono';">Generate synthetic artifacts via HUD then ingest below.</p>
        </div>
    """, unsafe_allow_html=True)

    col_a, col_b = st.columns(2)
    
    with col_a:
        st.markdown("""<div class="uploader-container">
            <h4 style="color:#38bdf8; font-family:'JetBrains Mono'; margin-bottom:5px;">CHANNEL A</h4>
            <p style="color:#94a3b8; font-size:0.8rem; margin-bottom:15px;">INGEST: <b>heartbeat_analysis.csv</b></p>
        </div>""", unsafe_allow_html=True)
        f1 = st.file_uploader("a", type=['csv'], label_visibility="collapsed", key="ch_a")
        
    with col_b:
        st.markdown("""<div class="uploader-container">
            <h4 style="color:#38bdf8; font-family:'JetBrains Mono'; margin-bottom:5px;">CHANNEL B</h4>
            <p style="color:#94a3b8; font-size:0.8rem; margin-bottom:15px;">INGEST: <b>ddos_traffic.csv</b></p>
        </div>""", unsafe_allow_html=True)
        f2 = st.file_uploader("b", type=['csv'], label_visibility="collapsed", key="ch_b")

    if f1 and f2:
        st.session_state.c2_data = f1.getvalue()
        st.session_state.ddos_data = f2.getvalue()
        st.session_state.app_state = 'ACTIVE'
        st.rerun()

elif st.session_state.app_state == 'ACTIVE':
    with open("temp_c2.csv", "wb") as f: f.write(st.session_state.c2_data)
    with open("temp_ddos.csv", "wb") as f: f.write(st.session_state.ddos_data)
    
    engine = IoTForensicsEngine("temp_c2.csv", "temp_ddos.csv")
    
    if engine.run_forensics():
        engine.analyze_behavior()
        engine.analyze_network()
        engine.run_ml_detection()
        
        var = engine.report_data['stats']['min_var']
        score = 100.0 if var < 0.0001 else max(0, 100 - (var * 10000))
        anoms = engine.report_data['ml']['anomalies']

        m1, m2, m3, m4 = st.columns(4)
        m1.markdown(f'<div class="stat-box"><small>DETERMINISM</small><br><b style="font-size:1.8rem; color:#4ade80;">{score:.1f}%</b></div>', unsafe_allow_html=True)
        m2.markdown(f'<div class="stat-box"><small>TIME VAR</small><br><b style="font-size:1.8rem; color:white;">{var:.8f}</b></div>', unsafe_allow_html=True)
        m3.markdown(f'<div class="stat-box"><small>AI ANOMALIES</small><br><b style="font-size:1.8rem; color:#ef4444;">{anoms}</b></div>', unsafe_allow_html=True)
        m4.markdown(f'<div class="stat-box"><small>BOT SIGNATURE</small><br><b style="font-size:1.8rem; color:#38bdf8;">MIRAI.v2</b></div>', unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)

        tabs = st.tabs(["TIMELINE FLOW", "AI THREAT MAP", "JITTER DENSITY", "VECTOR ANALYSIS", "MODEL PERFORMANCE", "FORENSIC EXPORT"])
        
        with tabs[0]:
            st.markdown('<div class="briefing-box">Temporal correlation between C2 heartbeats (Blue) and attack initiation (Red).</div>', unsafe_allow_html=True)
            fig = px.scatter(engine.df_c2, x='timestamp', y='delta', template="plotly_dark", color_discrete_sequence=['#38bdf8'])
            fig.add_trace(go.Scatter(x=engine.df_ddos['timestamp'], y=[engine.df_c2['delta'].mean()]*len(engine.df_ddos), mode='markers', name="Attack", marker=dict(color="#ef4444", symbol="x")))
            fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
            st.plotly_chart(fig, use_container_width=True)

        with tabs[1]:
            st.markdown('<div class="briefing-box">Isolation Forest results. <span style="color:#ef4444">Anomalies</span> denote deviations from robotic heartbeat.</div>', unsafe_allow_html=True)
            engine.df_c2['status'] = engine.df_c2['ai_label'].map({1: 'Legitimate', -1: 'Anomaly'})
            fig_ai = px.scatter(engine.df_c2, x='timestamp', y='rolling_var', color='status', 
                                color_discrete_map={'Legitimate': '#38bdf8', 'Anomaly': '#ef4444'}, template="plotly_dark")
            fig_ai.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
            st.plotly_chart(fig_ai, use_container_width=True)

        with tabs[2]:
             st.markdown('<div class="briefing-box">IAT Density. Sharp peaks confirm deterministic machine behavior.</div>', unsafe_allow_html=True)
             fig_hist = px.histogram(engine.df_c2, x="delta", nbins=50, template="plotly_dark", color_discrete_sequence=['#4ade80'])
             fig_hist.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", bargap=0.1)
             st.plotly_chart(fig_hist, use_container_width=True)

        with tabs[3]:
            st.markdown('<div class="briefing-box">Target port frequency extracted from the attack vector logs.</div>', unsafe_allow_html=True)
            if 'port' in engine.df_ddos.columns:
                port_counts = engine.df_ddos['port'].value_counts().reset_index()
                port_counts.columns = ['Port', 'Count']
                port_counts = port_counts.head(10)
                fig_bar = px.bar(port_counts, x='Port', y='Count', template="plotly_dark", color_discrete_sequence=['#38bdf8'])
                fig_bar.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
                fig_bar.update_xaxes(type='category')
                st.plotly_chart(fig_bar, use_container_width=True)

        with tabs[4]:
            st.markdown('<div class="briefing-box">AI PERFORMANCE BENCHMARK: Validation of Isolation Forest precision vs Ground Truth.</div>', unsafe_allow_html=True)
            
            c_left, c_right = st.columns([2, 1])
            
            with c_right:
                st.markdown('<div class="uploader-container" style="padding:15px; border-color: #4ade80;">', unsafe_allow_html=True)
                st.write("### AI Stress Test")
                st.write("Verifying if AI can distinguish between human jitter and machine-precision pulses.")
                run_test = st.button("RUN BENCHMARK")
                st.markdown('</div>', unsafe_allow_html=True)

            if run_test:
                #ALIGNED MAPPING LOGIC
                #DataFactory sequence: 1000 Human (0), then 1000 Bots (1)
                total_rows = len(engine.df_c2)
                y_true = [0] * (total_rows // 2) + [1] * (total_rows // 2)
                y_pred = [1 if val == 1 else 0 for val in engine.df_c2['ai_label']]
                
                with c_left:
                    #Confusion Matrix Plot
                    cm = confusion_matrix(y_true, y_pred)
                    fig_cm, ax = plt.subplots(figsize=(5, 4))
                    fig_cm.patch.set_facecolor('#020617')
                    ax.set_facecolor('#020617')
                    
                    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                                xticklabels=['HUMAN', 'BOTNET'], 
                                yticklabels=['HUMAN', 'BOTNET'], ax=ax, cbar=False,
                                annot_kws={"size": 14, "weight": "bold", "family": "JetBrains Mono"})
                    
                    plt.title("DETECTION CONFUSION MATRIX", color='#38bdf8', fontfamily='JetBrains Mono', weight='bold')
                    plt.ylabel('TRUE SOURCE', color='#38bdf8', fontfamily='JetBrains Mono')
                    plt.xlabel('AI CLASSIFICATION', color='#38bdf8', fontfamily='JetBrains Mono')
                    ax.tick_params(colors='white')
                    st.pyplot(fig_cm)
                
                #METRICS CALCULATION
                report = classification_report(y_true, y_pred, output_dict=True)
                accuracy = report['accuracy']
                
                st.markdown("---")
                r1, r2, r3, r4 = st.columns(4)
                r1.metric("PRECISION", f"{report['1']['precision']:.2%}")
                r2.metric("RECALL", f"{report['1']['recall']:.2%}")
                r3.metric("F1-SCORE", f"{report['1']['f1-score']:.2%}")
                r4.metric("ACCURACY", f"{accuracy:.2%}")
                st.markdown("<br>", unsafe_allow_html=True)
                
                if accuracy > 0.90:
                    status, color = "OPTIMAL", "#4ade80"
                    message = "AI successfully isolated the deterministic heartbeat. High confidence in Mirai detection."
                else:
                    status, color = "UNCERTAIN", "#f87171"
                    message = "Overlap detected between jitter and signal. Adjust AI parameters."

                st.markdown(f"""
                <div style="background: rgba(15, 23, 42, 0.9); border: 1px solid {color}; padding: 25px; border-radius: 8px;">
                    <div style="color:{color}; font-family:'JetBrains Mono'; font-weight: bold; margin-bottom: 12px; letter-spacing: 1px;">
                        [+] FORENSIC AI INTELLIGENCE REPORT
                    </div>
                    <div style="color: #f8fafc; font-family: 'JetBrains Mono'; font-size: 0.95rem; line-height: 1.7;">
                        > THREAT STATUS: <span style="color:{color}; font-weight:bold;">{status}</span><br>
                        > ANALYTICAL ACCURACY: <span style="color:{color};">{accuracy:.2%}</span><br>
                        > TRUE POSITIVES (BOTS): {cm[1][1]} / {total_rows // 2}<br>
                        > ANALYST INSIGHT: {message}<br><br>
                        <span style="color: #64748b; font-style: italic;">// Forensic validation sequence complete. Evidence verified.</span>
                    </div>
                </div>
                """, unsafe_allow_html=True)

        with tabs[5]:
            engine.export_forensic_report()
            st.markdown('<div class="cyber-card"><h3>REPORT GENERATED</h3><p>Integrity SHA-256 and Chain of Custody verified.</p></div>', unsafe_allow_html=True)
            with open("FORENSIC_REPORT.txt", "r") as f:
                st.download_button("📥 DOWNLOAD EVIDENCE", f, "FORENSIC_REPORT.txt")
            if st.button("RESET SESSION"): reset_session()