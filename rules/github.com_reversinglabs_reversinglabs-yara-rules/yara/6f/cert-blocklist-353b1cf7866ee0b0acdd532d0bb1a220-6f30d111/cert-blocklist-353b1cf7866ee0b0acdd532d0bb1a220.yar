import "pe"
rule cert_blocklist_353b1cf7866ee0b0acdd532d0bb1a220 {
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
            pe.signatures[i].subject contains "Network Freak Limited" and
            pe.signatures[i].serial == "35:3b:1c:f7:86:6e:e0:b0:ac:dd:53:2d:0b:b1:a2:20" and
            1558915200 <= pe.signatures[i].not_after
        )
}