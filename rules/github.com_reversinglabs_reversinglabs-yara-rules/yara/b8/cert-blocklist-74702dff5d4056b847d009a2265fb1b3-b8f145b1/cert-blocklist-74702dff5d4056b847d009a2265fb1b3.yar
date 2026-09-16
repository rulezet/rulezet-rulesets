import "pe"
rule cert_blocklist_74702dff5d4056b847d009a2265fb1b3 {
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
            pe.signatures[i].subject contains "Shulan Hou" and
            pe.signatures[i].serial == "74:70:2d:ff:5d:40:56:b8:47:d0:09:a2:26:5f:b1:b3" and
            1469664000 <= pe.signatures[i].not_after
        )
}