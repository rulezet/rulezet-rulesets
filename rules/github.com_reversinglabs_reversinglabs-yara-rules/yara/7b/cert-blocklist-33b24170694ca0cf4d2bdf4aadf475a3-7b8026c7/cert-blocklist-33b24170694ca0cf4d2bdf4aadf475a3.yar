import "pe"
rule cert_blocklist_33b24170694ca0cf4d2bdf4aadf475a3 {
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
            pe.signatures[i].subject contains "Yu Bao" and
            pe.signatures[i].serial == "33:b2:41:70:69:4c:a0:cf:4d:2b:df:4a:ad:f4:75:a3" and
            1474934400 <= pe.signatures[i].not_after
        )
}