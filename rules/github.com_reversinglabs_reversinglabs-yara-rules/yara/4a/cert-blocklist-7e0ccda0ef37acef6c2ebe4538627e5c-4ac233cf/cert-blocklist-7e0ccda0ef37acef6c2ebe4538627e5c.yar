import "pe"
rule cert_blocklist_7e0ccda0ef37acef6c2ebe4538627e5c {
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
            pe.signatures[i].subject contains "Orangetree B.V." and (
                pe.signatures[i].serial == "00:7e:0c:cd:a0:ef:37:ac:ef:6c:2e:be:45:38:62:7e:5c" or
                pe.signatures[i].serial == "7e:0c:cd:a0:ef:37:ac:ef:6c:2e:be:45:38:62:7e:5c"
            ) and
            1606159604 <= pe.signatures[i].not_after
        )
}