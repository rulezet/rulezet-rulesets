import "pe"
rule cert_blocklist_0ced87bd70b092cb93b182fac32655f6 {
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
            pe.signatures[i].subject contains "Creator Soft Limited" and
            pe.signatures[i].serial == "0c:ed:87:bd:70:b0:92:cb:93:b1:82:fa:c3:26:55:f6" and
            1614816000 <= pe.signatures[i].not_after
        )
}