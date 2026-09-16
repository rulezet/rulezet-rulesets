import "pe"
rule cert_blocklist_149c12083c145e28155510cfc19db0fe {
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
            pe.signatures[i].subject contains "3rd Eye Solutions Ltd" and
            pe.signatures[i].serial == "14:9c:12:08:3c:14:5e:28:15:55:10:cf:c1:9d:b0:fe" and
            1209340799 <= pe.signatures[i].not_after
        )
}