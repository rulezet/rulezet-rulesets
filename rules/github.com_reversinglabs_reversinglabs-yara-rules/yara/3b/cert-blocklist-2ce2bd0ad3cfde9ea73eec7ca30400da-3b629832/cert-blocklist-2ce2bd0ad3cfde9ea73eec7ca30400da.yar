import "pe"
rule cert_blocklist_2ce2bd0ad3cfde9ea73eec7ca30400da {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Media Lid" and
            pe.signatures[i].serial == "2c:e2:bd:0a:d3:cf:de:9e:a7:3e:ec:7c:a3:04:00:da" and
            1493337599 <= pe.signatures[i].not_after
        )
}