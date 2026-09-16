import "pe"
rule cert_blocklist_d875b3e3f2db6c3eb426e24946066111 {
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
            pe.signatures[i].subject contains "Kubit LLC" and (
                pe.signatures[i].serial == "00:d8:75:b3:e3:f2:db:6c:3e:b4:26:e2:49:46:06:61:11" or
                pe.signatures[i].serial == "d8:75:b3:e3:f2:db:6c:3e:b4:26:e2:49:46:06:61:11"
            ) and
            1606953600 <= pe.signatures[i].not_after
        )
}