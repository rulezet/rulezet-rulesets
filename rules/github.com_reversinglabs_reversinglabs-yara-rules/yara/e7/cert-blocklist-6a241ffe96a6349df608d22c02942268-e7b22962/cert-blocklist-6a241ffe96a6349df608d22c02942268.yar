import "pe"
rule cert_blocklist_6a241ffe96a6349df608d22c02942268 {
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
            pe.signatures[i].subject contains "HELP, d.o.o." and
            pe.signatures[i].serial == "6a:24:1f:fe:96:a6:34:9d:f6:08:d2:2c:02:94:22:68" and
            1605052800 <= pe.signatures[i].not_after
        )
}