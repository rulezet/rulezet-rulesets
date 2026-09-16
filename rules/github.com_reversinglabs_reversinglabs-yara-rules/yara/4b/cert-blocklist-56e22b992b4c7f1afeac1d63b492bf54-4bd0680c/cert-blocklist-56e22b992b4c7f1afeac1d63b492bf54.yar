import "pe"
rule cert_blocklist_56e22b992b4c7f1afeac1d63b492bf54 {
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
            pe.signatures[i].subject contains "Open Source Developer, Hetem Ramadani" and
            pe.signatures[i].serial == "56:e2:2b:99:2b:4c:7f:1a:fe:ac:1d:63:b4:92:bf:54" and
            1435622399 <= pe.signatures[i].not_after
        )
}