import "pe"
rule cert_blocklist_2c16be9a7ce2a23ab7a4b4eb7da3400c {
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
            pe.signatures[i].subject contains "Prince city music bar" and
            pe.signatures[i].serial == "2c:16:be:9a:7c:e2:a2:3a:b7:a4:b4:eb:7d:a3:40:0c" and
            1371081600 <= pe.signatures[i].not_after
        )
}