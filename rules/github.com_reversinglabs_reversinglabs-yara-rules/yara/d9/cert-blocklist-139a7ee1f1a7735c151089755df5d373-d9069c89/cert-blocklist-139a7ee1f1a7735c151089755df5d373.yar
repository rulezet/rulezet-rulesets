import "pe"
rule cert_blocklist_139a7ee1f1a7735c151089755df5d373 {
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
            pe.signatures[i].subject contains "Yongli Li" and
            pe.signatures[i].serial == "13:9a:7e:e1:f1:a7:73:5c:15:10:89:75:5d:f5:d3:73" and
            1476057600 <= pe.signatures[i].not_after
        )
}