import "pe"
rule cert_blocklist_09c89de6f64a7fdf657e69353c5fdd44 {
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
            pe.signatures[i].subject contains "EXON RENTAL SP Z O O" and
            pe.signatures[i].serial == "09:c8:9d:e6:f6:4a:7f:df:65:7e:69:35:3c:5f:dd:44" and
            1601337601 <= pe.signatures[i].not_after
        )
}