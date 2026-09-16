import "pe"
rule cert_blocklist_02c5351936abe405ac760228a40387e8 {
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
            pe.signatures[i].subject contains "RESURS-RM OOO" and
            pe.signatures[i].serial == "02:c5:35:19:36:ab:e4:05:ac:76:02:28:a4:03:87:e8" and
            1589932801 <= pe.signatures[i].not_after
        )
}