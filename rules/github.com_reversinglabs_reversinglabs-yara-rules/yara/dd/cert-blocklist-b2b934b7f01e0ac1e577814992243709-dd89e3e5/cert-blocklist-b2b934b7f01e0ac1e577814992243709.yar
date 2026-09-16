import "pe"
rule cert_blocklist_b2b934b7f01e0ac1e577814992243709 {
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
            pe.signatures[i].subject contains "MS CORP SOFTWARE LTD" and (
                pe.signatures[i].serial == "00:b2:b9:34:b7:f0:1e:0a:c1:e5:77:81:49:92:24:37:09" or
                pe.signatures[i].serial == "b2:b9:34:b7:f0:1e:0a:c1:e5:77:81:49:92:24:37:09"
            ) and
            1590710400 <= pe.signatures[i].not_after
        )
}