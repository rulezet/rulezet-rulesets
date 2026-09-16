import "pe"
rule cert_blocklist_db95b22362d46a73c39e0ac924883c5b {
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
            pe.signatures[i].subject contains "SPSLTD PLYMOUTH LTD" and (
                pe.signatures[i].serial == "00:db:95:b2:23:62:d4:6a:73:c3:9e:0a:c9:24:88:3c:5b" or
                pe.signatures[i].serial == "db:95:b2:23:62:d4:6a:73:c3:9e:0a:c9:24:88:3c:5b"
            ) and
            1621296000 <= pe.signatures[i].not_after
        )
}