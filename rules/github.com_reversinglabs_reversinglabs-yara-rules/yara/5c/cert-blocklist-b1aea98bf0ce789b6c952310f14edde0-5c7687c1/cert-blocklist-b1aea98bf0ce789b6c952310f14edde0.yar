import "pe"
rule cert_blocklist_b1aea98bf0ce789b6c952310f14edde0 {
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
            pe.signatures[i].subject contains "Absolut LLC" and (
                pe.signatures[i].serial == "00:b1:ae:a9:8b:f0:ce:78:9b:6c:95:23:10:f1:4e:dd:e0" or
                pe.signatures[i].serial == "b1:ae:a9:8b:f0:ce:78:9b:6c:95:23:10:f1:4e:dd:e0"
            ) and
            1602612570 <= pe.signatures[i].not_after
        )
}