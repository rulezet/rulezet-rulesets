import "pe"
rule cert_blocklist_6e2d3449272b6b96b8b9f728e87580d5 {
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
            pe.signatures[i].subject contains "RADIANT, OOO" and
            pe.signatures[i].serial == "6e:2d:34:49:27:2b:6b:96:b8:b9:f7:28:e8:75:80:d5" and
            1421107200 <= pe.signatures[i].not_after
        )
}