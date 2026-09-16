import "pe"
rule cert_blocklist_18b700a319aa98ae71b279d4e8030b82 {
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
            pe.signatures[i].serial == "18:b7:00:a3:19:aa:98:ae:71:b2:79:d4:e8:03:0b:82" and
            1479686400 <= pe.signatures[i].not_after
        )
}