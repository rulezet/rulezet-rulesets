import "pe"
rule cert_blocklist_b2120facadbb92cc0a176759604c6a0f {
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
            pe.signatures[i].subject contains "SLON LTD" and (
                pe.signatures[i].serial == "00:b2:12:0f:ac:ad:bb:92:cc:0a:17:67:59:60:4c:6a:0f" or
                pe.signatures[i].serial == "b2:12:0f:ac:ad:bb:92:cc:0a:17:67:59:60:4c:6a:0f"
            ) and
            1554249600 <= pe.signatures[i].not_after
        )
}