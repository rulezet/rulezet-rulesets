import "pe"
rule cert_blocklist_4fc13d6220c629043a26f81b1cad72d8 {
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
            pe.signatures[i].subject contains "Open Source Developer, meicun ge" and
            pe.signatures[i].serial == "4f:c1:3d:62:20:c6:29:04:3a:26:f8:1b:1c:ad:72:d8" and
            1404172799 <= pe.signatures[i].not_after
        )
}