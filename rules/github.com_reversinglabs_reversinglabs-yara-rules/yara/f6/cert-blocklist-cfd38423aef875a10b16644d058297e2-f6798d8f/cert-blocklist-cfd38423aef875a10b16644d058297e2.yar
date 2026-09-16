import "pe"
rule cert_blocklist_cfd38423aef875a10b16644d058297e2 {
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
            pe.signatures[i].subject contains "TRUST DANMARK ApS" and (
                pe.signatures[i].serial == "00:cf:d3:84:23:ae:f8:75:a1:0b:16:64:4d:05:82:97:e2" or
                pe.signatures[i].serial == "cf:d3:84:23:ae:f8:75:a1:0b:16:64:4d:05:82:97:e2"
            ) and
            1632884040 <= pe.signatures[i].not_after
        )
}