import "pe"
rule cert_blocklist_0e6f4cb8b06e01c3bd296ace3a95f814 {
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
            pe.signatures[i].subject contains "EVATON, s.r.o." and
            pe.signatures[i].serial == "0e:6f:4c:b8:b0:6e:01:c3:bd:29:6a:ce:3a:95:f8:14" and
            1603957781 <= pe.signatures[i].not_after
        )
}