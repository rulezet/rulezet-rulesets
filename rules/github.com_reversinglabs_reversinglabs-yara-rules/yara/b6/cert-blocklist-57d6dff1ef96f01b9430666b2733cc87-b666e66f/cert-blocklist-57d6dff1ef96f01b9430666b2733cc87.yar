import "pe"
rule cert_blocklist_57d6dff1ef96f01b9430666b2733cc87 {
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
            pe.signatures[i].subject contains "Smart Plugin Ltda" and
            pe.signatures[i].serial == "57:d6:df:f1:ef:96:f0:1b:94:30:66:6b:27:33:cc:87" and
            1314575999 <= pe.signatures[i].not_after
        )
}