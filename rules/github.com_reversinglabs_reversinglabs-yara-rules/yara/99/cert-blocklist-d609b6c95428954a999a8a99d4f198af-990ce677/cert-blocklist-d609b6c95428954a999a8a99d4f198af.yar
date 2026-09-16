import "pe"
rule cert_blocklist_d609b6c95428954a999a8a99d4f198af {
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
            pe.signatures[i].subject contains "OOO Fudl" and (
                pe.signatures[i].serial == "00:d6:09:b6:c9:54:28:95:4a:99:9a:8a:99:d4:f1:98:af" or
                pe.signatures[i].serial == "d6:09:b6:c9:54:28:95:4a:99:9a:8a:99:d4:f1:98:af"
            ) and
            1612828800 <= pe.signatures[i].not_after
        )
}