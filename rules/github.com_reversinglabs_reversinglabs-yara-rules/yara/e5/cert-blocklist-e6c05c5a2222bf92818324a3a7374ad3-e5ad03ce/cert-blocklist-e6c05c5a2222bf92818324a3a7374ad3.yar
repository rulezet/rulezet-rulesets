import "pe"
rule cert_blocklist_e6c05c5a2222bf92818324a3a7374ad3 {
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
            pe.signatures[i].subject contains "ANAQA EVENTS LTD" and (
                pe.signatures[i].serial == "00:e6:c0:5c:5a:22:22:bf:92:81:83:24:a3:a7:37:4a:d3" or
                pe.signatures[i].serial == "e6:c0:5c:5a:22:22:bf:92:81:83:24:a3:a7:37:4a:d3"
            ) and
            1634720407 <= pe.signatures[i].not_after
        )
}