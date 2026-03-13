#!/usr/bin/env python3
"""
Test script for Juice Shop Login SQLi Detector
Run this when Juice Shop is available at http://localhost:3000
"""
import asyncio
import sys

async def test_detector(target_url: str = "http://localhost:3000"):
    print("="*60)
    print("Juice Shop Login SQLi Detector - Test")
    print("="*60)
    print(f"Target: {target_url}")
    print()
    
    try:
        # Check if Juice Shop is available
        import requests
        resp = requests.get(target_url, timeout=5)
        if resp.status_code != 200:
            print(f"❌ Juice Shop not available at {target_url} (status: {resp.status_code})")
            print("\nStart Juice Shop first:")
            print("  docker run -d -p 3000:3000 bkimminich/juice-shop")
            print("  OR")
            print("  cd juice-shop && npm start")
            return
        
        print(f"✓ Juice Shop is running (status: {resp.status_code})")
        
    except requests.exceptions.ConnectionError:
        print(f"❌ Cannot connect to {target_url}")
        print("\nStart Juice Shop:")
        print("  docker run -d -p 3000:3000 bkimminich/juice-shop")
        return
    except Exception as e:
        print(f"❌ Error: {e}")
        return
    
    # Import detector
    try:
        from juice_login_sqli import JuiceShopLoginSQLiDetector
        print("✓ Detector module loaded")
    except Exception as e:
        print(f"❌ Import error: {e}")
        return
    
    # Run detector
    from playwright.async_api import async_playwright
    
    print("\nStarting detection...\n")
    
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context()
        page = await context.new_page()
        
        detector = JuiceShopLoginSQLiDetector(
            page=page,
            target_url=target_url,
            timeout=30000
        )
        
        findings = await detector.detect_login_sqli()
        
        await browser.close()
    
    # Print results
    print("\n" + "="*60)
    print("RESULTS")
    print("="*60)
    
    if findings:
        print(f"\n🎯 FOUND {len(findings)} AUTHENTICATION BYPASS VULNERABILITIES!\n")
        
        for i, finding in enumerate(findings, 1):
            print(f"{i}. {finding.vulnerability_type.value.upper()}")
            print(f"   Severity: {finding.severity}")
            print(f"   Payload: {finding.payload}")
            print(f"   Evidence: {finding.evidence}")
            if finding.jwt_token:
                print(f"   JWT: {finding.jwt_token[:60]}...")
            print(f"   Confidence: {finding.confidence:.0%}")
            print()
    else:
        print("\n❌ No vulnerabilities found")
        print("\nPossible reasons:")
        print("  - Juice Shop already patched")
        print("  - Network timeout")
        print("  - Detection logic needs tuning")
    
    # Summary
    summary = detector.get_findings_summary()
    print("="*60)
    print("SUMMARY")
    print("="*60)
    print(f"Payloads tested: {summary.get('payloads_tested', 0)}")
    print(f"Requests intercepted: {summary.get('requests_intercepted', 0)}")
    print(f"Responses captured: {summary.get('responses_captured', 0)}")
    print(f"Findings: {summary.get('total', 0)}")
    
    return len(findings) > 0


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:3000"
    
    success = asyncio.run(test_detector(target))
    
    sys.exit(0 if success else 1)
