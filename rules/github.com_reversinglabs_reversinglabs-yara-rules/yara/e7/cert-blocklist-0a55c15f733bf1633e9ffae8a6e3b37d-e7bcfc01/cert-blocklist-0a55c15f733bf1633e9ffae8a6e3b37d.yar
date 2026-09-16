import "pe"
rule cert_blocklist_0a55c15f733bf1633e9ffae8a6e3b37d {
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
            pe.signatures[i].subject contains "Osnova OOO" and
            pe.signatures[i].serial == "0a:55:c1:5f:73:3b:f1:63:3e:9f:fa:e8:a6:e3:b3:7d" and
            1604016000 <= pe.signatures[i].not_after
        )
}