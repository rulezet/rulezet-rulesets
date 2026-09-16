import "pe"
rule cert_blocklist_64c2505c7306639fc8eae544b0305338 {
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
            pe.signatures[i].subject contains "MANILA Solution as" and
            pe.signatures[i].serial == "64:c2:50:5c:73:06:63:9f:c8:ea:e5:44:b0:30:53:38" and
            1609418043 <= pe.signatures[i].not_after
        )
}