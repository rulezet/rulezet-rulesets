import "pe"
rule cert_blocklist_57fc55239f21f139978609e323097132 {
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
            pe.signatures[i].subject contains "Aidem Media Limited" and
            pe.signatures[i].serial == "57:fc:55:23:9f:21:f1:39:97:86:09:e3:23:09:71:32" and
            1501632000 <= pe.signatures[i].not_after
        )
}