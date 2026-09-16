import "pe"
rule cert_blocklist_40f5660a90301e7a8a8c3b42 {
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
            pe.signatures[i].subject contains "Booz Allen Hamilton Inc." and
            pe.signatures[i].serial == "40:f5:66:0a:90:30:1e:7a:8a:8c:3b:42" and
            1641833688 <= pe.signatures[i].not_after
        )
}