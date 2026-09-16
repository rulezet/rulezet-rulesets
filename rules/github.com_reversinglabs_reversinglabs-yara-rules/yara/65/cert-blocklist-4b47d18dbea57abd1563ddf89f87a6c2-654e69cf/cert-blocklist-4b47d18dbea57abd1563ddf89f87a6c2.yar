import "pe"
rule cert_blocklist_4b47d18dbea57abd1563ddf89f87a6c2 {
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
            pe.signatures[i].subject contains "KBK, OOO" and
            pe.signatures[i].serial == "4b:47:d1:8d:be:a5:7a:bd:15:63:dd:f8:9f:87:a6:c2" and
            1590485607 <= pe.signatures[i].not_after
        )
}