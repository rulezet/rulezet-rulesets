import "pe"
rule cert_blocklist_881573fc67ff7395dde5bccfbce5b088 {
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
            pe.signatures[i].subject contains "Trade in Brasil s.r.o." and (
                pe.signatures[i].serial == "00:88:15:73:fc:67:ff:73:95:dd:e5:bc:cf:bc:e5:b0:88" or
                pe.signatures[i].serial == "88:15:73:fc:67:ff:73:95:dd:e5:bc:cf:bc:e5:b0:88"
            ) and
            1620000000 <= pe.signatures[i].not_after
        )
}