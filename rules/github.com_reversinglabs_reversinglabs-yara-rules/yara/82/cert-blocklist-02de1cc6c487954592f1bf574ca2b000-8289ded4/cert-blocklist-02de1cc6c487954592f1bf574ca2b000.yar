import "pe"
rule cert_blocklist_02de1cc6c487954592f1bf574ca2b000 {
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
            pe.signatures[i].subject contains "Orca System" and
            pe.signatures[i].serial == "02:de:1c:c6:c4:87:95:45:92:f1:bf:57:4c:a2:b0:00" and
            1613735394 <= pe.signatures[i].not_after
        )
}