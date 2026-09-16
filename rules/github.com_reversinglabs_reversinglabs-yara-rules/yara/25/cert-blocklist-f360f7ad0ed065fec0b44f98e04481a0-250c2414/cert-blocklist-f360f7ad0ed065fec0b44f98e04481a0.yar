import "pe"
rule cert_blocklist_f360f7ad0ed065fec0b44f98e04481a0 {
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
            pe.signatures[i].subject contains "MEHANIKUM OOO" and (
                pe.signatures[i].serial == "00:f3:60:f7:ad:0e:d0:65:fe:c0:b4:4f:98:e0:44:81:a0" or
                pe.signatures[i].serial == "f3:60:f7:ad:0e:d0:65:fe:c0:b4:4f:98:e0:44:81:a0"
            ) and
            1599031121 <= pe.signatures[i].not_after
        )
}