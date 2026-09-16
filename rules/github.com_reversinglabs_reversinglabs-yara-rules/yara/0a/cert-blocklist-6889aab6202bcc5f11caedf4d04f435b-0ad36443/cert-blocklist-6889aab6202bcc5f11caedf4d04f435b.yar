import "pe"
rule cert_blocklist_6889aab6202bcc5f11caedf4d04f435b {
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
            pe.signatures[i].subject contains "C4DL Media" and
            pe.signatures[i].serial == "68:89:aa:b6:20:2b:cc:5f:11:ca:ed:f4:d0:4f:43:5b" and
            1231891200 <= pe.signatures[i].not_after
        )
}