import "pe"
rule cert_blocklist_5b1c3f7bbaa91ca49b06a5c1004ee5be {
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
            pe.signatures[i].subject contains "Jin Yuguang" and
            pe.signatures[i].serial == "5b:1c:3f:7b:ba:a9:1c:a4:9b:06:a5:c1:00:4e:e5:be" and
            1440643213 <= pe.signatures[i].not_after
        )
}