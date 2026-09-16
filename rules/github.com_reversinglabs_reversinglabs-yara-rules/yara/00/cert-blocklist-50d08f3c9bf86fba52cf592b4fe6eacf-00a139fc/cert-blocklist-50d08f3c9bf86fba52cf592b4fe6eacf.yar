import "pe"
rule cert_blocklist_50d08f3c9bf86fba52cf592b4fe6eacf {
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
            pe.signatures[i].subject contains "CLEVERCYBER LTD" and
            pe.signatures[i].serial == "50:d0:8f:3c:9b:f8:6f:ba:52:cf:59:2b:4f:e6:ea:cf" and
            1518134400 <= pe.signatures[i].not_after
        )
}