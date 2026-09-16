import "pe"
rule cert_blocklist_ebbdd6cdeda40ca64513280ecd625c54 {
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
            pe.signatures[i].subject contains "IT PUT LIMITED" and (
                pe.signatures[i].serial == "00:eb:bd:d6:cd:ed:a4:0c:a6:45:13:28:0e:cd:62:5c:54" or
                pe.signatures[i].serial == "eb:bd:d6:cd:ed:a4:0c:a6:45:13:28:0e:cd:62:5c:54"
            ) and
            1549238400 <= pe.signatures[i].not_after
        )
}