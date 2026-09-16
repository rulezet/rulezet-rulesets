import "pe"
rule cert_blocklist_0bab6a2aa84b495d9e554a4c42c0126d {
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
            pe.signatures[i].subject contains "NOSOV SP Z O O" and
            pe.signatures[i].serial == "0b:ab:6a:2a:a8:4b:49:5d:9e:55:4a:4c:42:c0:12:6d" and
            1597971600 <= pe.signatures[i].not_after
        )
}