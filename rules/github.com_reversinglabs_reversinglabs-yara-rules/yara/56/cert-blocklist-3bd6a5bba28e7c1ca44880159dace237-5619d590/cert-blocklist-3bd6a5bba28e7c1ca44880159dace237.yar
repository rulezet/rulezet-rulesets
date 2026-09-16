import "pe"
rule cert_blocklist_3bd6a5bba28e7c1ca44880159dace237 {
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
            pe.signatures[i].subject contains "TECHNO BEAVERS LIMITED" and
            pe.signatures[i].serial == "3b:d6:a5:bb:a2:8e:7c:1c:a4:48:80:15:9d:ac:e2:37" and
            1563408000 <= pe.signatures[i].not_after
        )
}