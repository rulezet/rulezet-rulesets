import "pe"
rule cert_blocklist_07cef66a71c35bc3aed6d100c6493863 {
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
            pe.signatures[i].subject contains "Fubon Technologies Ltd" and
            pe.signatures[i].serial == "07:ce:f6:6a:71:c3:5b:c3:ae:d6:d1:00:c6:49:38:63" and
            1602740890 <= pe.signatures[i].not_after
        )
}