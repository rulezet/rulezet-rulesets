import "pe"
rule cert_blocklist_6724340ddbc7252f7fb714b812a5c04d {
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
            pe.signatures[i].subject contains "YNK JAPAN Inc" and
            pe.signatures[i].serial == "67:24:34:0d:db:c7:25:2f:7f:b7:14:b8:12:a5:c0:4d" and
            1306195199 <= pe.signatures[i].not_after
        )
}