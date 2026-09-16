import "pe"
rule cert_blocklist_094bf19d509d3074913995160b195b6c {
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
            pe.signatures[i].subject contains "Porral Twinware S.L.L." and
            pe.signatures[i].serial == "09:4b:f1:9d:50:9d:30:74:91:39:95:16:0b:19:5b:6c" and
            1373241599 <= pe.signatures[i].not_after
        )
}