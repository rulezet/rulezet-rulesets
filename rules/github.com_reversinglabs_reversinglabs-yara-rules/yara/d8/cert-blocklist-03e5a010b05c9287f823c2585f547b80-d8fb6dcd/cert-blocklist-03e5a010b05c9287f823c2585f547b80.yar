import "pe"
rule cert_blocklist_03e5a010b05c9287f823c2585f547b80 {
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
            pe.signatures[i].subject contains "MOCOMSYS INC" and
            pe.signatures[i].serial == "03:e5:a0:10:b0:5c:92:87:f8:23:c2:58:5f:54:7b:80" and
            1385423999 <= pe.signatures[i].not_after
        )
}