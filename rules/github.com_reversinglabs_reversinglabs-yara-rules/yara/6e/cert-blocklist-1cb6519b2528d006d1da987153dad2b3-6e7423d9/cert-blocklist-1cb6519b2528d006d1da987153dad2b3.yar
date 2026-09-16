import "pe"
rule cert_blocklist_1cb6519b2528d006d1da987153dad2b3 {
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
            pe.signatures[i].subject contains "D and D Internet Services" and
            pe.signatures[i].serial == "1c:b6:51:9b:25:28:d0:06:d1:da:98:71:53:da:d2:b3" and
            1012780800 <= pe.signatures[i].not_after
        )
}