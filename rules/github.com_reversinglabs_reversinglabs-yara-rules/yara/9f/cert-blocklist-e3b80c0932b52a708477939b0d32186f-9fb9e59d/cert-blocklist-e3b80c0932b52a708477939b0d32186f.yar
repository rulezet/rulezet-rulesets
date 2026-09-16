import "pe"
rule cert_blocklist_e3b80c0932b52a708477939b0d32186f {
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
            pe.signatures[i].subject contains "BISOYETUTU LTD LIMITED" and (
                pe.signatures[i].serial == "00:e3:b8:0c:09:32:b5:2a:70:84:77:93:9b:0d:32:18:6f" or
                pe.signatures[i].serial == "e3:b8:0c:09:32:b5:2a:70:84:77:93:9b:0d:32:18:6f"
            ) and
            1617062400 <= pe.signatures[i].not_after
        )
}