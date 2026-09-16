import "pe"
rule cert_blocklist_35590ebe4a02dc23317d8ce47a947a9b {
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
            pe.signatures[i].subject contains "OOO Largos" and
            pe.signatures[i].serial == "35:59:0e:be:4a:02:dc:23:31:7d:8c:e4:7a:94:7a:9b" and
            1602201600 <= pe.signatures[i].not_after
        )
}