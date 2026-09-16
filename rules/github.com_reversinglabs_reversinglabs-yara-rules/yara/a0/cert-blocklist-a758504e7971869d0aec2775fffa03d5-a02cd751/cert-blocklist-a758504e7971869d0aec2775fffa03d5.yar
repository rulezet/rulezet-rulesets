import "pe"
rule cert_blocklist_a758504e7971869d0aec2775fffa03d5 {
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
            pe.signatures[i].subject contains "Amcert LLC" and (
                pe.signatures[i].serial == "00:a7:58:50:4e:79:71:86:9d:0a:ec:27:75:ff:fa:03:d5" or
                pe.signatures[i].serial == "a7:58:50:4e:79:71:86:9d:0a:ec:27:75:ff:fa:03:d5"
            ) and
            1623628800 <= pe.signatures[i].not_after
        )
}