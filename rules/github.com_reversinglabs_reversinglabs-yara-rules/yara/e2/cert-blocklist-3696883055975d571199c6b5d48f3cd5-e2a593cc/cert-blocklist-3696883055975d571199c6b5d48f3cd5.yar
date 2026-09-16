import "pe"
rule cert_blocklist_3696883055975d571199c6b5d48f3cd5 {
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
            pe.signatures[i].subject contains "Korist Networks Incorporated" and
            pe.signatures[i].serial == "36:96:88:30:55:97:5d:57:11:99:c6:b5:d4:8f:3c:d5" and
            1600069289 <= pe.signatures[i].not_after
        )
}