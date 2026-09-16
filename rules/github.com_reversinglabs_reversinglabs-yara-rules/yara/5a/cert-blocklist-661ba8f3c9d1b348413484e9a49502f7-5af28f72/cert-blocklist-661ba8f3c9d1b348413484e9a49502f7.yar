import "pe"
rule cert_blocklist_661ba8f3c9d1b348413484e9a49502f7 {
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
            pe.signatures[i].subject contains "Unique Digital Services Ltd." and (
                pe.signatures[i].serial == "00:66:1b:a8:f3:c9:d1:b3:48:41:34:84:e9:a4:95:02:f7" or
                pe.signatures[i].serial == "66:1b:a8:f3:c9:d1:b3:48:41:34:84:e9:a4:95:02:f7"
            ) and
            1594942800 <= pe.signatures[i].not_after
        )
}