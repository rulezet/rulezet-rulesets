import "pe"
rule cert_blocklist_6401831b46588b9d872b02076c3a7b00 {
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
            pe.signatures[i].subject contains "ACTIV GROUP ApS" and
            pe.signatures[i].serial == "64:01:83:1b:46:58:8b:9d:87:2b:02:07:6c:3a:7b:00" and
            1615507200 <= pe.signatures[i].not_after
        )
}