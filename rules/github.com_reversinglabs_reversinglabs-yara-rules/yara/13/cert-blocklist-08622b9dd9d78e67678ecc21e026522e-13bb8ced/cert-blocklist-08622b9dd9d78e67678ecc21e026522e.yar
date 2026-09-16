import "pe"
rule cert_blocklist_08622b9dd9d78e67678ecc21e026522e {
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
            pe.signatures[i].subject contains "Kayak Republic af 2015 APS" and
            pe.signatures[i].serial == "08:62:2b:9d:d9:d7:8e:67:67:8e:cc:21:e0:26:52:2e" and
            1611619200 <= pe.signatures[i].not_after
        )
}