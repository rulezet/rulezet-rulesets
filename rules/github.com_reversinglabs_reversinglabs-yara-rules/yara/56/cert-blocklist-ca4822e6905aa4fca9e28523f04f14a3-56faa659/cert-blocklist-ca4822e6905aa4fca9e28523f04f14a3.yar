import "pe"
rule cert_blocklist_ca4822e6905aa4fca9e28523f04f14a3 {
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
            pe.signatures[i].subject contains "ELISTREID, OOO" and (
                pe.signatures[i].serial == "00:ca:48:22:e6:90:5a:a4:fc:a9:e2:85:23:f0:4f:14:a3" or
                pe.signatures[i].serial == "ca:48:22:e6:90:5a:a4:fc:a9:e2:85:23:f0:4f:14:a3"
            ) and
            1614643200 <= pe.signatures[i].not_after
        )
}