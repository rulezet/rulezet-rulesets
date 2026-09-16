import "pe"
rule cert_blocklist_2924785fd7990b2d510675176dae2bed {
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
            pe.signatures[i].subject contains "Neoopt LLC" and
            pe.signatures[i].serial == "29:24:78:5f:d7:99:0b:2d:51:06:75:17:6d:ae:2b:ed" and
            1595000258 <= pe.signatures[i].not_after
        )
}