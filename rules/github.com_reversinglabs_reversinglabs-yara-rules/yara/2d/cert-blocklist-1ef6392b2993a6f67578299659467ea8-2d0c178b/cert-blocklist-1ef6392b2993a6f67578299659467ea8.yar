import "pe"
rule cert_blocklist_1ef6392b2993a6f67578299659467ea8 {
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
            pe.signatures[i].subject contains "ALUSEN d. o. o." and
            pe.signatures[i].serial == "1e:f6:39:2b:29:93:a6:f6:75:78:29:96:59:46:7e:a8" and
            1618531200 <= pe.signatures[i].not_after
        )
}