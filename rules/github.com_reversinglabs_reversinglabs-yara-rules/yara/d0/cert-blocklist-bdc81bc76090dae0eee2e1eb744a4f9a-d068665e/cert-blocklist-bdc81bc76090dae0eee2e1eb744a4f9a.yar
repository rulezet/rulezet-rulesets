import "pe"
rule cert_blocklist_bdc81bc76090dae0eee2e1eb744a4f9a {
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
            pe.signatures[i].subject contains "ALM4U GmbH" and (
                pe.signatures[i].serial == "00:bd:c8:1b:c7:60:90:da:e0:ee:e2:e1:eb:74:4a:4f:9a" or
                pe.signatures[i].serial == "bd:c8:1b:c7:60:90:da:e0:ee:e2:e1:eb:74:4a:4f:9a"
            ) and
            1579824000 <= pe.signatures[i].not_after
        )
}