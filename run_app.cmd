@echo off
cd /d "%~dp0"
echo Starting Streamlit app...
python -m streamlit run src/dashboard/app.py
