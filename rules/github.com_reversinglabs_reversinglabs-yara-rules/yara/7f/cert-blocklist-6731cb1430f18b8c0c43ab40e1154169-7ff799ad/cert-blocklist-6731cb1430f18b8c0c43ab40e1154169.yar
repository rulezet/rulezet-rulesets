import "pe"
rule cert_blocklist_6731cb1430f18b8c0c43ab40e1154169 {
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
            pe.signatures[i].subject contains "3 AM CHP" and
            pe.signatures[i].serial == "67:31:cb:14:30:f1:8b:8c:0c:43:ab:40:e1:15:41:69" and
            1436313600 <= pe.signatures[i].not_after
        )
}