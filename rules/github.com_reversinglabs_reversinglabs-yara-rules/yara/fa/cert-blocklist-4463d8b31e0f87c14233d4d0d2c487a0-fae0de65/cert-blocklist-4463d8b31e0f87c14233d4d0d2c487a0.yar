import "pe"
rule cert_blocklist_4463d8b31e0f87c14233d4d0d2c487a0 {
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
            pe.signatures[i].subject contains "Yu Bao" and
            pe.signatures[i].serial == "44:63:d8:b3:1e:0f:87:c1:42:33:d4:d0:d2:c4:87:a0" and
            1477612800 <= pe.signatures[i].not_after
        )
}