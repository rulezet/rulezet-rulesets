import "pe"
rule cert_blocklist_1deea179f5757fe529043577762419df {
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
            pe.signatures[i].subject contains "SPIRIT CONSULTING s. r. o." and
            pe.signatures[i].serial == "1d:ee:a1:79:f5:75:7f:e5:29:04:35:77:76:24:19:df" and
            1645401600 <= pe.signatures[i].not_after
        )
}