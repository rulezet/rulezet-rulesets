import "pe"
rule cert_blocklist_066276af2f2c7e246d3b1cab1b4aa42e {
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
            pe.signatures[i].subject contains "IQ Trade ApS" and
            pe.signatures[i].serial == "06:62:76:af:2f:2c:7e:24:6d:3b:1c:ab:1b:4a:a4:2e" and
            1616630400 <= pe.signatures[i].not_after
        )
}