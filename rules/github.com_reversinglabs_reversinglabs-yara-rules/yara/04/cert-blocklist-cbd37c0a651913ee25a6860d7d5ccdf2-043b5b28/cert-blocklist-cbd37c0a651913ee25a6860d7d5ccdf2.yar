import "pe"
rule cert_blocklist_cbd37c0a651913ee25a6860d7d5ccdf2 {
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
            pe.signatures[i].subject contains "Amma" and (
                pe.signatures[i].serial == "00:cb:d3:7c:0a:65:19:13:ee:25:a6:86:0d:7d:5c:cd:f2" or
                pe.signatures[i].serial == "cb:d3:7c:0a:65:19:13:ee:25:a6:86:0d:7d:5c:cd:f2"
            ) and
            1431734400 <= pe.signatures[i].not_after
        )
}