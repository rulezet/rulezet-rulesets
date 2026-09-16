import "pe"
rule cert_blocklist_5b440a47e8ce3dd202271e5c7a666c78 {
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
            pe.signatures[i].subject contains "Master Networking s.r.o." and
            pe.signatures[i].serial == "5b:44:0a:47:e8:ce:3d:d2:02:27:1e:5c:7a:66:6c:78" and
            1601895571 <= pe.signatures[i].not_after
        )
}