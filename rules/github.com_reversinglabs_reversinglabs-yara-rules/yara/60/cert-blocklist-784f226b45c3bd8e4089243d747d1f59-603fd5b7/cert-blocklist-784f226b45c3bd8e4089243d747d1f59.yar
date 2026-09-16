import "pe"
rule cert_blocklist_784f226b45c3bd8e4089243d747d1f59 {
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
            pe.signatures[i].subject contains "FSPro Labs" and
            pe.signatures[i].serial == "78:4f:22:6b:45:c3:bd:8e:40:89:24:3d:74:7d:1f:59" and
            1242777599 <= pe.signatures[i].not_after
        )
}