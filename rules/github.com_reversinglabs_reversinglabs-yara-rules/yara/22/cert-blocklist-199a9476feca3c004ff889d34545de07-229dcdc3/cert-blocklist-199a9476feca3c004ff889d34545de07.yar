import "pe"
rule cert_blocklist_199a9476feca3c004ff889d34545de07 {
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
            pe.signatures[i].subject contains "Funcall" and
            pe.signatures[i].serial == "19:9a:94:76:fe:ca:3c:00:4f:f8:89:d3:45:45:de:07" and
            1138060800 <= pe.signatures[i].not_after
        )
}