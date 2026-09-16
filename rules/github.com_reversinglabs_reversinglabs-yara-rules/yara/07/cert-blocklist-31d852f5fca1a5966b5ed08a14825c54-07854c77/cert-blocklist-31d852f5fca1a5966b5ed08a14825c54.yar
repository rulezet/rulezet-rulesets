import "pe"
rule cert_blocklist_31d852f5fca1a5966b5ed08a14825c54 {
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
            pe.signatures[i].subject contains "BBT KLA d.o.o." and
            pe.signatures[i].serial == "31:d8:52:f5:fc:a1:a5:96:6b:5e:d0:8a:14:82:5c:54" and
            1612396800 <= pe.signatures[i].not_after
        )
}