@echo off
cd /d "%~dp0"
"C:/Users/nethr/AppData/Local/Programs/Python/Python314/python.exe" -c "from src.analysis.unified_analysis import analyze_all; d=analyze_all(); print(d['protocols']); print(d['tcp']); print(d['dns']); print(d['arp'])"
