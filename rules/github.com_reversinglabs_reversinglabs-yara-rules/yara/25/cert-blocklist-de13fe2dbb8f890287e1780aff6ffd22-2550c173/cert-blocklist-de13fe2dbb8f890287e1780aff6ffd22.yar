import "pe"
rule cert_blocklist_de13fe2dbb8f890287e1780aff6ffd22 {
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
            pe.signatures[i].subject contains "LAST TIME PTY LTD" and
            pe.signatures[i].serial == "de:13:fe:2d:bb:8f:89:02:87:e1:78:0a:ff:6f:fd:22" and
            1566259200 <= pe.signatures[i].not_after
        )
}