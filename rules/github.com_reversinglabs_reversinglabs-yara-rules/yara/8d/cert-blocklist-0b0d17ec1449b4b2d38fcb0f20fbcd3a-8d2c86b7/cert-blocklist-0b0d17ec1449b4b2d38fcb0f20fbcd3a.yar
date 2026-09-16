import "pe"
rule cert_blocklist_0b0d17ec1449b4b2d38fcb0f20fbcd3a {
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
            pe.signatures[i].subject contains "WEBPIC DESENVOLVIMENTO DE SOFTWARE LTDA" and
            pe.signatures[i].serial == "0b:0d:17:ec:14:49:b4:b2:d3:8f:cb:0f:20:fb:cd:3a" and
            1394150399 <= pe.signatures[i].not_after
        )
}