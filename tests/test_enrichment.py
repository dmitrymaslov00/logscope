from logscope.enrichment import enrich_alert
from logscope.storage import init_db, insert_enriched_alert
from contextlib import closing
import sqlite3
import json



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


def test_init_db_creates_alerts_table(tmp_path):
    p = tmp_path / 'test.db'

    init_db(p)

    with closing(sqlite3.connect(p)) as conn:
        with conn:
            cursor = conn.execute("""
                SELECT name FROM sqlite_master WHERE type='table' AND name='alerts'
            """)

            rows = cursor.fetchall()


    assert len(rows) == 1


def test_insert_enriched_alert(tmp_path, make_alert, monkeypatch):
    p = tmp_path / 'test.db'

    init_db(p)

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

    insert_enriched_alert(p, enriched_alert)

    with closing(sqlite3.connect(p)) as conn:
        with conn:
            cursor = conn.execute("""
                SELECT * FROM alerts
            """)

            rows = cursor.fetchall()

    assert len(rows) == 1

    row = rows[0]

    assert row[0] is not None
    assert row[1] == 'ssh_brute_force'
    assert row[2] == '203.0.113.5'
    assert row[3] == 5
    assert row[4] == '2026-10-19T01:41:00+00:00'
    assert row[5] == '2026-10-19T01:41:55+00:00'

    abuseipdb = json.loads(row[6])

    assert abuseipdb["score"] == 30
    assert abuseipdb["reports"] == 205
    assert abuseipdb["country"] == 'US'
    assert abuseipdb["isp"] == 'Spectrum'


def test_insert_enriched_alert_with_provider_error(tmp_path, make_alert, monkeypatch):
    p = tmp_path / 'test.db'
    
    init_db(p)

    alert = make_alert()
        
    def fake_check_ip(ip, api_key):
        assert ip == alert.src_ip
        assert api_key == 'fake-key'
        return {"error": "Network error"}

    monkeypatch.setattr("logscope.enrichment.check_ip", fake_check_ip)

    enriched_alert = enrich_alert(alert, 'fake-key')

    insert_enriched_alert(p, enriched_alert)
    
    with closing(sqlite3.connect(p)) as conn:
        with conn:
            cursor = conn.execute("""
                SELECT * FROM alerts
            """)

            rows = cursor.fetchall()

    assert len(rows) == 1
    
    row = rows[0]

    assert row[0] is not None
    assert row[1] == 'ssh_brute_force'
    assert row[2] == '203.0.113.5'
    assert row[3] == 5
    assert row[4] == '2026-10-19T01:41:00+00:00'
    assert row[5] == '2026-10-19T01:41:55+00:00'

    abuseipdb = json.loads(row[6])

    assert abuseipdb["error"] == 'Network error'