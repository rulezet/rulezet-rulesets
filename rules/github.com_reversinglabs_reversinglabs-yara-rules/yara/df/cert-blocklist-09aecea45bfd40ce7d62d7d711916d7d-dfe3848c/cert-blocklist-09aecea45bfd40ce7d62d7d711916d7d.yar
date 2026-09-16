import "pe"
rule cert_blocklist_09aecea45bfd40ce7d62d7d711916d7d {
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
            pe.signatures[i].subject contains "ALINA LTD" and
            pe.signatures[i].serial == "09:ae:ce:a4:5b:fd:40:ce:7d:62:d7:d7:11:91:6d:7d" and
            1551052800 <= pe.signatures[i].not_after
        )
}