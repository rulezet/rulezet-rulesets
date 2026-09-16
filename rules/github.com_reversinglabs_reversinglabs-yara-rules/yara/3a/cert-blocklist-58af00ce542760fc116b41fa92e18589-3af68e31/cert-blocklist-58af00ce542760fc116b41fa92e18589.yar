import "pe"
rule cert_blocklist_58af00ce542760fc116b41fa92e18589 {
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
            pe.signatures[i].subject contains "DICKIE MUSDALE WINDFARM LIMITED" and
            pe.signatures[i].serial == "58:af:00:ce:54:27:60:fc:11:6b:41:fa:92:e1:85:89" and
            1654819200 <= pe.signatures[i].not_after
        )
}