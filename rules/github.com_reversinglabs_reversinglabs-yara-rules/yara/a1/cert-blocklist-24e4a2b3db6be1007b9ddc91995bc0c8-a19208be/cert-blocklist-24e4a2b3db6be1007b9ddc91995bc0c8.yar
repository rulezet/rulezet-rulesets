import "pe"
rule cert_blocklist_24e4a2b3db6be1007b9ddc91995bc0c8 {
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
            pe.signatures[i].subject contains "FLY BETTER s.r.o." and
            pe.signatures[i].serial == "24:e4:a2:b3:db:6b:e1:00:7b:9d:dc:91:99:5b:c0:c8" and
            1645142400 <= pe.signatures[i].not_after
        )
}