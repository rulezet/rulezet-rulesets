import "pe"
rule cert_blocklist_5fbf16a33d26390a15f046c310030cf0 {
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
            pe.signatures[i].subject contains "MACHINES SATU MARE SRL" and
            pe.signatures[i].serial == "5f:bf:16:a3:3d:26:39:0a:15:f0:46:c3:10:03:0c:f0" and
            1638390070 <= pe.signatures[i].not_after
        )
}