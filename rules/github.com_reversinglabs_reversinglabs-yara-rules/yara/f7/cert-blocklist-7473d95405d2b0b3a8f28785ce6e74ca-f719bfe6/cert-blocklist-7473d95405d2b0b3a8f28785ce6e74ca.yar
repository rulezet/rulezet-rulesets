import "pe"
rule cert_blocklist_7473d95405d2b0b3a8f28785ce6e74ca {
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
            pe.signatures[i].subject contains "Dmitrij Emelyanov" and
            pe.signatures[i].serial == "74:73:d9:54:05:d2:b0:b3:a8:f2:87:85:ce:6e:74:ca" and
            1453939199 <= pe.signatures[i].not_after
        )
}