import "pe"
rule cert_blocklist_202702 {
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
            pe.signatures[i].subject contains "RDCTO Ltd" and
            pe.signatures[i].serial == "20:27:02" and
            1087391361 <= pe.signatures[i].not_after
        )
}