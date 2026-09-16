import "pe"
rule cert_blocklist_7903870184e18a80899740845a15e2b2 {
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
            pe.signatures[i].subject contains "Qool Aid, LLC" and
            pe.signatures[i].serial == "79:03:87:01:84:e1:8a:80:89:97:40:84:5a:15:e2:b2" and
            1079654400 <= pe.signatures[i].not_after
        )
}