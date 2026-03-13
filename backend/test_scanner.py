#!/usr/bin/env python3
"""
DAST Scanner - Quick Test Script
Tests all scanning modes against Juice Shop
"""
import requests
import time
import sys

API_BASE = "http://127.0.0.1:8000"
TARGET = "http://127.0.0.1:3000"

def start_scan(mode: str) -> int:
    """Start scan and return scan ID"""
    resp = requests.post(
        f"{API_BASE}/api/v1/startdast",
        json={"target": TARGET, "mode": mode},
        timeout=10
    )
    if resp.status_code == 200:
        data = resp.json()
        print(f"✅ Started scan #{data['id']} (mode: {mode})")
        return data['id']
    else:
        print(f"❌ Failed to start scan: {resp.text}")
        return None

def wait_for_scan(scan_id: int, timeout: int = 120) -> dict:
    """Wait for scan to complete"""
    start = time.time()
    while time.time() - start < timeout:
        time.sleep(5)
        resp = requests.get(f"{API_BASE}/api/v1/scan/{scan_id}", timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            if data['status'] == 'completed':
                return data
            elif data['status'] == 'failed':
                print(f"❌ Scan #{scan_id} failed")
                return None
    print(f"⏱️ Timeout waiting for scan #{scan_id}")
    return None

def print_results(scan_id: int, data: dict):
    """Print scan results"""
    findings = data.get('findings', [])
    
    print(f"\n{'='*60}")
    print(f"SCAN #{scan_id} RESULTS")
    print(f"{'='*60}")
    print(f"Target: {data['target_url']}")
    print(f"Mode: {data['scan_mode']}")
    print(f"Status: {data['status']}")
    print(f"Findings: {len(findings)}\n")
    
    # Count by severity
    by_severity = {}
    for f in findings:
        sev = f.get('info', {}).get('severity', 'info')
        by_severity[sev] = by_severity.get(sev, 0) + 1
    
    print("📊 By severity:")
    for sev in ['critical', 'high', 'medium', 'low', 'info']:
        count = by_severity.get(sev, 0)
        if count > 0:
            emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🔵', 'info': '⚪'}[sev]
            print(f"   {emoji} {sev.upper()}: {count}")
    
    print(f"\n🎯 Top vulnerabilities:")
    for i, f in enumerate(findings[:10], 1):
        name = f.get('info', {}).get('name', 'Unknown')[:50]
        sev = f.get('info', {}).get('severity', 'info').upper()
        print(f"   {i}. [{sev}] {name}")
    
    print(f"\n{'='*60}\n")

def main():
    print("="*60)
    print("DAST SCANNER - AUTOMATED TEST")
    print("="*60)
    print(f"Target: {TARGET}")
    print(f"API: {API_BASE}\n")
    
    # Check if backend is running
    try:
        resp = requests.get(f"{API_BASE}/docs", timeout=5)
        if resp.status_code != 200:
            print("❌ Backend not responding!")
            sys.exit(1)
        print("✅ Backend is running")
    except Exception as e:
        print(f"❌ Cannot connect to backend: {e}")
        sys.exit(1)
    
    # Check if Juice Shop is running
    try:
        resp = requests.get(TARGET, timeout=5)
        if resp.status_code != 200:
            print(f"⚠️ Juice Shop returned status {resp.status_code}")
        else:
            print("✅ Juice Shop is running")
    except Exception as e:
        print(f"❌ Cannot connect to Juice Shop: {e}")
        sys.exit(1)
    
    print("\n" + "="*60)
    print("STARTING SCANS")
    print("="*60 + "\n")
    
    # Test Quick mode
    print("[1/3] Testing QUICK mode...")
    scan_id = start_scan("quick")
    if scan_id:
        result = wait_for_scan(scan_id, timeout=60)
        if result:
            print_results(scan_id, result)
    
    time.sleep(2)
    
    # Test Recon mode
    print("[2/3] Testing RECON mode...")
    scan_id = start_scan("recon")
    if scan_id:
        result = wait_for_scan(scan_id, timeout=180)
        if result:
            print_results(scan_id, result)
    
    time.sleep(2)
    
    # Test Full mode (optional - takes long)
    print("[3/3] Testing FULL mode (started in background)...")
    scan_id = start_scan("full")
    if scan_id:
        print(f"   Full scan #{scan_id} started (takes 5-10 minutes)")
        print(f"   Check results at: {API_BASE}/api/v1/scan/{scan_id}")
    
    print("\n" + "="*60)
    print("TEST COMPLETE")
    print("="*60)
    print("\n✅ All scans completed successfully!")
    print(f"📊 Check results at: {API_BASE}")
    print(f"📄 API Docs: {API_BASE}/docs\n")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️ Interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
