import "pe"
rule cert_blocklist_ff52eb011bb748fee75153cbe1e50dd6 {
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
            pe.signatures[i].subject contains "TASK ANNA LIMITED" and (
                pe.signatures[i].serial == "00:ff:52:eb:01:1b:b7:48:fe:e7:51:53:cb:e1:e5:0d:d6" or
                pe.signatures[i].serial == "ff:52:eb:01:1b:b7:48:fe:e7:51:53:cb:e1:e5:0d:d6"
            ) and
            1647388800 <= pe.signatures[i].not_after
        )
}