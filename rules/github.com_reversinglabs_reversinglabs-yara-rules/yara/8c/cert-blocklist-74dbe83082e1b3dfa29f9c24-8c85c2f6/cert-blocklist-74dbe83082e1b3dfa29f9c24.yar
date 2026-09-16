import "pe"
rule cert_blocklist_74dbe83082e1b3dfa29f9c24 {
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
            pe.signatures[i].subject contains "EVANGEL TECHNOLOGY(HK) LIMITED" and
            pe.signatures[i].serial == "74:db:e8:30:82:e1:b3:df:a2:9f:9c:24" and
            1468817578 <= pe.signatures[i].not_after
        )
}