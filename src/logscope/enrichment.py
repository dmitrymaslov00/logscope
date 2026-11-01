from logscope.models import Alert, EnrichedAlert
from ioc_enricher.providers.abuseipdb import check_ip


def enrich_alert(alert: Alert, api_key: str) -> EnrichedAlert:
    enriched_ip = check_ip(alert.src_ip, api_key)

    return EnrichedAlert(
        alert=alert,
        abuseipdb=enriched_ip
    )