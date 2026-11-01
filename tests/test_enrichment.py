from logscope.enrichment import enrich_alert



def test_enrich_alert_stores_provider_response(make_alert, monkeypatch):
    alert = make_alert()

    abuseipdb_test_answer = {
        "score": 30,
        "reports": 205,
        "country": "US",
        "isp": "Spectrum"
    }
    

    def fake_check_ip(ip, api_key):
        assert ip == alert.src_ip
        assert api_key == 'fake-key'
        return abuseipdb_test_answer

    monkeypatch.setattr("logscope.enrichment.check_ip", fake_check_ip)

    enriched_alert = enrich_alert(alert, 'fake-key')

    assert enriched_alert.alert == alert
    assert enriched_alert.alert.count == 5
    assert enriched_alert.alert.src_ip == '203.0.113.5'

    assert enriched_alert.abuseipdb["score"] == 30
    assert enriched_alert.abuseipdb["reports"] == 205
    assert enriched_alert.abuseipdb["country"] == 'US'
    assert enriched_alert.abuseipdb["isp"] == 'Spectrum'


def test_enrich_alert_preserves_provider_error(make_alert, monkeypatch):
    alert = make_alert()
    

    def fake_check_ip(ip, api_key):
        assert ip == alert.src_ip
        assert api_key == 'fake-key'
        return {"error": "Network error"}

    monkeypatch.setattr("logscope.enrichment.check_ip", fake_check_ip)

    enriched_alert = enrich_alert(alert, 'fake-key')

    assert enriched_alert.alert == alert
    assert enriched_alert.alert.count == 5
    assert enriched_alert.alert.src_ip == '203.0.113.5'

    assert enriched_alert.abuseipdb["error"] == "Network error"
