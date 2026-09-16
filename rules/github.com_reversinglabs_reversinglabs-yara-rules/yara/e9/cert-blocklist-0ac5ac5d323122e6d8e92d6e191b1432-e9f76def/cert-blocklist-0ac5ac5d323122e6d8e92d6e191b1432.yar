import "pe"
rule cert_blocklist_0ac5ac5d323122e6d8e92d6e191b1432 {
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
            pe.signatures[i].subject contains "Certified Software" and
            pe.signatures[i].serial == "0a:c5:ac:5d:32:31:22:e6:d8:e9:2d:6e:19:1b:14:32" and
            1140134400 <= pe.signatures[i].not_after
        )
}