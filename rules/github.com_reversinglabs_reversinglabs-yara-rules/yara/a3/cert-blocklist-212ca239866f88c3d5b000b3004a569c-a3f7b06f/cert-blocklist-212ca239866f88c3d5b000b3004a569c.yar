import "pe"
rule cert_blocklist_212ca239866f88c3d5b000b3004a569c {
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
            pe.signatures[i].subject contains "XECURE LAB CO., LTD." and
            pe.signatures[i].serial == "21:2c:a2:39:86:6f:88:c3:d5:b0:00:b3:00:4a:56:9c" and
            1347840000 <= pe.signatures[i].not_after
        )
}