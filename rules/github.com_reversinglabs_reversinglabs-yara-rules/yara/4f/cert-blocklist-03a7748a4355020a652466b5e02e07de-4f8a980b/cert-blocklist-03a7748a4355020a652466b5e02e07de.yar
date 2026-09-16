import "pe"
rule cert_blocklist_03a7748a4355020a652466b5e02e07de {
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
            pe.signatures[i].subject contains "Teleneras MB" and
            pe.signatures[i].serial == "03:a7:74:8a:43:55:02:0a:65:24:66:b5:e0:2e:07:de" and
            1575244801 <= pe.signatures[i].not_after
        )
}