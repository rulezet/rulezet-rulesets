import "pe"
rule cert_blocklist_123a5074069162f4ed68fc7d48f464c2 {
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
            pe.signatures[i].subject contains "Yu Bao" and
            pe.signatures[i].serial == "12:3a:50:74:06:91:62:f4:ed:68:fc:7d:48:f4:64:c2" and
            1472428800 <= pe.signatures[i].not_after
        )
}