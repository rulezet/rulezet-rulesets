import "pe"
rule cert_blocklist_954d0577d5ce8999e0387a5364829f66 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Soblosol Limited" and (
                pe.signatures[i].serial == "00:95:4d:05:77:d5:ce:89:99:e0:38:7a:53:64:82:9f:66" or
                pe.signatures[i].serial == "95:4d:05:77:d5:ce:89:99:e0:38:7a:53:64:82:9f:66"
            ) and
            1543968000 <= pe.signatures[i].not_after
        )
}