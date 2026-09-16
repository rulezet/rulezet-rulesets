import "pe"
rule cert_blocklist_69a72f5591ad78a0825fbb9402ab9543 {
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
            pe.signatures[i].subject contains "PUSH BANK LIMITED" and
            pe.signatures[i].serial == "69:a7:2f:55:91:ad:78:a0:82:5f:bb:94:02:ab:95:43" and
            1581811200 <= pe.signatures[i].not_after
        )
}