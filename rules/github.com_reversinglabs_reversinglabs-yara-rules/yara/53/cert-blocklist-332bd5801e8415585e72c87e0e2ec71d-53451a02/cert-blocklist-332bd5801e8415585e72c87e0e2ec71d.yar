import "pe"
rule cert_blocklist_332bd5801e8415585e72c87e0e2ec71d {
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
            pe.signatures[i].subject contains "Elite Marketing Strategies, Inc." and
            pe.signatures[i].serial == "33:2b:d5:80:1e:84:15:58:5e:72:c8:7e:0e:2e:c7:1d" and
            1662616824 <= pe.signatures[i].not_after
        )
}