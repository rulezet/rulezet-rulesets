import "pe"
rule cert_blocklist_3457a918c6d3701b2eaca6a92474a7cc {
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
            pe.signatures[i].subject contains "KONSALTING PLUS OOO" and
            pe.signatures[i].serial == "34:57:a9:18:c6:d3:70:1b:2e:ac:a6:a9:24:74:a7:cc" and
            1432252799 <= pe.signatures[i].not_after
        )
}