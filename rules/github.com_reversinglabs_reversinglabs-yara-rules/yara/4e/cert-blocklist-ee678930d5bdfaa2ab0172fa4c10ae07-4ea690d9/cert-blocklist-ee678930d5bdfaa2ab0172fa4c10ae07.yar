import "pe"
rule cert_blocklist_ee678930d5bdfaa2ab0172fa4c10ae07 {
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
            pe.signatures[i].subject contains "LEX CORPORATION PTY LTD" and (
                pe.signatures[i].serial == "00:ee:67:89:30:d5:bd:fa:a2:ab:01:72:fa:4c:10:ae:07" or
                pe.signatures[i].serial == "ee:67:89:30:d5:bd:fa:a2:ab:01:72:fa:4c:10:ae:07"
            ) and
            1571011200 <= pe.signatures[i].not_after
        )
}