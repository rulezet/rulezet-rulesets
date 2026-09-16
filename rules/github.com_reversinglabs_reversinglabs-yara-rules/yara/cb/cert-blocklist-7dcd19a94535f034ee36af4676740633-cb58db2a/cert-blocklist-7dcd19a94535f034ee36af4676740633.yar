import "pe"
rule cert_blocklist_7dcd19a94535f034ee36af4676740633 {
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
            pe.signatures[i].subject contains "Toko Saya ApS" and
            pe.signatures[i].serial == "7d:cd:19:a9:45:35:f0:34:ee:36:af:46:76:74:06:33" and
            1609200000 <= pe.signatures[i].not_after
        )
}