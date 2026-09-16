import "pe"
rule cert_blocklist_032660ee1d49ad35086027473e2614e5e724 {
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
            pe.signatures[i].subject contains "sunshine.com" and
            pe.signatures[i].serial == "03:26:60:ee:1d:49:ad:35:08:60:27:47:3e:26:14:e5:e7:24" and
            1660238245 <= pe.signatures[i].not_after
        )
}