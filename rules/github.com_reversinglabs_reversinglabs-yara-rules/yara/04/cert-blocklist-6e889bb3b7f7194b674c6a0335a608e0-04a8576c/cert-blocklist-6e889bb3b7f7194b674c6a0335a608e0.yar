import "pe"
rule cert_blocklist_6e889bb3b7f7194b674c6a0335a608e0 {
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
            pe.signatures[i].subject contains "CLEVERCONTROL LLC" and
            pe.signatures[i].serial == "6e:88:9b:b3:b7:f7:19:4b:67:4c:6a:03:35:a6:08:e0" and
            1646956800 <= pe.signatures[i].not_after
        )
}