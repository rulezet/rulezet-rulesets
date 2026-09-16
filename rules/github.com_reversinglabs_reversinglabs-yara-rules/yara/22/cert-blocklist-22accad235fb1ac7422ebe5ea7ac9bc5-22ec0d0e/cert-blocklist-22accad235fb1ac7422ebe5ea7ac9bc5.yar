import "pe"
rule cert_blocklist_22accad235fb1ac7422ebe5ea7ac9bc5 {
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
            pe.signatures[i].subject contains "IMS INTERACTIVE MEDIA SOLUTIONS" and
            pe.signatures[i].serial == "22:ac:ca:d2:35:fb:1a:c7:42:2e:be:5e:a7:ac:9b:c5" and
            1019001600 <= pe.signatures[i].not_after
        )
}