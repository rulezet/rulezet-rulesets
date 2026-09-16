import "pe"
rule cert_blocklist_846f77d9919fc4405aefe1701309bd67 {
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
            pe.signatures[i].subject contains "IPM Skupina d.o.o." and (
                pe.signatures[i].serial == "00:84:6f:77:d9:91:9f:c4:40:5a:ef:e1:70:13:09:bd:67" or
                pe.signatures[i].serial == "84:6f:77:d9:91:9f:c4:40:5a:ef:e1:70:13:09:bd:67"
            ) and
            1621382400 <= pe.signatures[i].not_after
        )
}