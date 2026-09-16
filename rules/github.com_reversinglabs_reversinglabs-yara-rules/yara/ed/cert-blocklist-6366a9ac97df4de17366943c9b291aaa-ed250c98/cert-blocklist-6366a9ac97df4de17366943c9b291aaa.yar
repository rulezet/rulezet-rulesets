import "pe"
rule cert_blocklist_6366a9ac97df4de17366943c9b291aaa {
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
            pe.signatures[i].subject contains "xlgames" and
            pe.signatures[i].serial == "63:66:a9:ac:97:df:4d:e1:73:66:94:3c:9b:29:1a:aa" and
            1326796477 <= pe.signatures[i].not_after
        )
}