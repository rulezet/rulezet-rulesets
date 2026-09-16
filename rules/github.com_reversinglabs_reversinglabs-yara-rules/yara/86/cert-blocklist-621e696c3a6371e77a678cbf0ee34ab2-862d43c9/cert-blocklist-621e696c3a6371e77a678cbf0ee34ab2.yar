import "pe"
rule cert_blocklist_621e696c3a6371e77a678cbf0ee34ab2 {
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
            pe.signatures[i].subject contains "Yu Bao" and
            pe.signatures[i].serial == "62:1e:69:6c:3a:63:71:e7:7a:67:8c:bf:0e:e3:4a:b2" and
            1467072000 <= pe.signatures[i].not_after
        )
}