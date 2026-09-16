import "pe"
rule cert_blocklist_621ed8265b0ad872d9f4b4ed6d560513 {
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
            pe.signatures[i].subject contains "Fan Li" and
            pe.signatures[i].serial == "62:1e:d8:26:5b:0a:d8:72:d9:f4:b4:ed:6d:56:05:13" and
            1413183357 <= pe.signatures[i].not_after
        )
}