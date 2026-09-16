import "pe"
rule cert_blocklist_476de2f108d20b43ba3bae6f331af8f1 {
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
            pe.signatures[i].subject contains "Digiwill Limited" and
            pe.signatures[i].serial == "47:6d:e2:f1:08:d2:0b:43:ba:3b:ae:6f:33:1a:f8:f1" and
            1588135722 <= pe.signatures[i].not_after
        )
}