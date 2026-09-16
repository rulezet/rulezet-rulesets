import "pe"
rule cert_blocklist_73ecfdbb99aec176ddfcf7958d120e1a {
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
            pe.signatures[i].subject contains "MHOW PTY LTD" and
            pe.signatures[i].serial == "73:ec:fd:bb:99:ae:c1:76:dd:fc:f7:95:8d:12:0e:1a" and
            1566864000 <= pe.signatures[i].not_after
        )
}