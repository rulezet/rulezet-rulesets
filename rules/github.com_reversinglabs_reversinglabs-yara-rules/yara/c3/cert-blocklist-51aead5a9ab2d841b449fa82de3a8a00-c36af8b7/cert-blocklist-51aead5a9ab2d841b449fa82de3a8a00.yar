import "pe"
rule cert_blocklist_51aead5a9ab2d841b449fa82de3a8a00 {
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
            pe.signatures[i].subject contains "Corsair Software Solution Inc." and
            pe.signatures[i].serial == "51:ae:ad:5a:9a:b2:d8:41:b4:49:fa:82:de:3a:8a:00" and
            1501577475 <= pe.signatures[i].not_after
        )
}