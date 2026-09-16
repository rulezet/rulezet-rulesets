import "pe"
rule cert_blocklist_4728189fa0f57793484cdf764f5e283d {
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
            pe.signatures[i].subject contains "Power Save Systems s.r.o." and
            pe.signatures[i].serial == "47:28:18:9f:a0:f5:77:93:48:4c:df:76:4f:5e:28:3d" and
            1647302400 <= pe.signatures[i].not_after
        )
}