import "pe"
rule cert_blocklist_486bbddc8c5ee99f051ecaeb3f99d2a3 {
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
            pe.signatures[i].subject contains "Xin Zhou" and
            pe.signatures[i].serial == "48:6b:bd:dc:8c:5e:e9:9f:05:1e:ca:eb:3f:99:d2:a3" and
            1473292800 <= pe.signatures[i].not_after
        )
}