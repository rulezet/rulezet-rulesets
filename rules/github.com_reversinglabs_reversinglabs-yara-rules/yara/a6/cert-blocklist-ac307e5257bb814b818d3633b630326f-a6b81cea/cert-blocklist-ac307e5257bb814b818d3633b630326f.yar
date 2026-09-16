import "pe"
rule cert_blocklist_ac307e5257bb814b818d3633b630326f {
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
            pe.signatures[i].subject contains "Aqua Direct s.r.o." and (
                pe.signatures[i].serial == "00:ac:30:7e:52:57:bb:81:4b:81:8d:36:33:b6:30:32:6f" or
                pe.signatures[i].serial == "ac:30:7e:52:57:bb:81:4b:81:8d:36:33:b6:30:32:6f"
            ) and
            1606089600 <= pe.signatures[i].not_after
        )
}