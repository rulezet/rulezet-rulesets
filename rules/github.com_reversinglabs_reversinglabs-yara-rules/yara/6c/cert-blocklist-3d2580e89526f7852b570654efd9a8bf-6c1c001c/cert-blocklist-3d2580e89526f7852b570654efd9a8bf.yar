import "pe"
rule cert_blocklist_3d2580e89526f7852b570654efd9a8bf {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing LockerGoga ransomware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "MIKL LIMITED" and
            pe.signatures[i].serial == "3d:25:80:e8:95:26:f7:85:2b:57:06:54:ef:d9:a8:bf" and
            1529888400 <= pe.signatures[i].not_after
        )
}