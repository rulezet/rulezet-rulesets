import "pe"
rule cert_blocklist_0747f6a8c3542f954b113fd98c7607cf {
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
            pe.signatures[i].subject contains "Xin Zhou" and
            pe.signatures[i].serial == "07:47:f6:a8:c3:54:2f:95:4b:11:3f:d9:8c:76:07:cf" and
            1474329600 <= pe.signatures[i].not_after
        )
}