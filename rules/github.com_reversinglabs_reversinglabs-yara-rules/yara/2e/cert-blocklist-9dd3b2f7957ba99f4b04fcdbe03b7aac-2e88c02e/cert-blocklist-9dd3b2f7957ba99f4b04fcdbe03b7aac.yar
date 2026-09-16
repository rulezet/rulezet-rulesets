import "pe"
rule cert_blocklist_9dd3b2f7957ba99f4b04fcdbe03b7aac {
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
            pe.signatures[i].subject contains "DOD MEDIA LIMITED" and (
                pe.signatures[i].serial == "00:9d:d3:b2:f7:95:7b:a9:9f:4b:04:fc:db:e0:3b:7a:ac" or
                pe.signatures[i].serial == "9d:d3:b2:f7:95:7b:a9:9f:4b:04:fc:db:e0:3b:7a:ac"
            ) and
            1646438400 <= pe.signatures[i].not_after
        )
}