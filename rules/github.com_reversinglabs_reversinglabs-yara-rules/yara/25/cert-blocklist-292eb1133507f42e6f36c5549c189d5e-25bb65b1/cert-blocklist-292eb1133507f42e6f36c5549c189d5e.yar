import "pe"
rule cert_blocklist_292eb1133507f42e6f36c5549c189d5e {
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
            pe.signatures[i].subject contains "Affairs-case s.r.o." and
            pe.signatures[i].serial == "29:2e:b1:13:35:07:f4:2e:6f:36:c5:54:9c:18:9d:5e" and
            1638832273 <= pe.signatures[i].not_after
        )
}