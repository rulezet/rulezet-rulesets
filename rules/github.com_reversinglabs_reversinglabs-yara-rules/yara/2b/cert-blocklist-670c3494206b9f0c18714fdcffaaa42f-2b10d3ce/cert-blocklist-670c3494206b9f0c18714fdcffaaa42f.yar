import "pe"
rule cert_blocklist_670c3494206b9f0c18714fdcffaaa42f {
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
            pe.signatures[i].subject contains "ADRIATIK PORT SERVIS, d.o.o." and
            pe.signatures[i].serial == "67:0c:34:94:20:6b:9f:0c:18:71:4f:dc:ff:aa:a4:2f" and
            1622160000 <= pe.signatures[i].not_after
        )
}