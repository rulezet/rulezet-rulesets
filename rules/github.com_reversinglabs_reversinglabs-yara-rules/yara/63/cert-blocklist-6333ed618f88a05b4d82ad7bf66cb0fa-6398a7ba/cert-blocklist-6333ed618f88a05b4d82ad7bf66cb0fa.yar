import "pe"
rule cert_blocklist_6333ed618f88a05b4d82ad7bf66cb0fa {
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
            pe.signatures[i].subject contains "RHM LIMITED" and
            pe.signatures[i].serial == "63:33:ed:61:8f:88:a0:5b:4d:82:ad:7b:f6:6c:b0:fa" and
            1616457600 <= pe.signatures[i].not_after
        )
}