import "pe"
rule cert_blocklist_8385684419ab26a3f2640b1496e1fe94 {
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
            pe.signatures[i].subject contains "CAUSE FOR CHANGE LTD" and (
                pe.signatures[i].serial == "00:83:85:68:44:19:ab:26:a3:f2:64:0b:14:96:e1:fe:94" or
                pe.signatures[i].serial == "83:85:68:44:19:ab:26:a3:f2:64:0b:14:96:e1:fe:94"
            ) and
            1612137600 <= pe.signatures[i].not_after
        )
}