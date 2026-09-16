import "pe"
rule cert_blocklist_70e1ebd170db8102d8c28e58392e5632 {
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
            pe.signatures[i].subject contains "Equal Cash Technologies Limited" and
            pe.signatures[i].serial == "70:e1:eb:d1:70:db:81:02:d8:c2:8e:58:39:2e:56:32" and
            1599264000 <= pe.signatures[i].not_after
        )
}