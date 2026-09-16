import "pe"
rule cert_blocklist_7d27332c3cb3a382a4fd232c5c66a2 {
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
            pe.signatures[i].subject contains "MALVINA RECRUITMENT LIMITED" and
            pe.signatures[i].serial == "7d:27:33:2c:3c:b3:a3:82:a4:fd:23:2c:5c:66:a2" and
            1655424000 <= pe.signatures[i].not_after
        )
}