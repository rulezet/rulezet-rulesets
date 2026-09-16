import "pe"
rule cert_blocklist_c2fc83d458e653837fcfc132c9b03062 {
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
            pe.signatures[i].subject contains "OOO Vertical" and (
                pe.signatures[i].serial == "00:c2:fc:83:d4:58:e6:53:83:7f:cf:c1:32:c9:b0:30:62" or
                pe.signatures[i].serial == "c2:fc:83:d4:58:e6:53:83:7f:cf:c1:32:c9:b0:30:62"
            ) and
            1602201600 <= pe.signatures[i].not_after
        )
}