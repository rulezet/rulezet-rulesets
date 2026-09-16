import "pe"
rule cert_blocklist_06df5c318759d6ea9d090bfb2faf1d94 {
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
            pe.signatures[i].subject contains "SpiffyTech Inc." and
            pe.signatures[i].serial == "06:df:5c:31:87:59:d6:ea:9d:09:0b:fb:2f:af:1d:94" and
            1634515201 <= pe.signatures[i].not_after
        )
}