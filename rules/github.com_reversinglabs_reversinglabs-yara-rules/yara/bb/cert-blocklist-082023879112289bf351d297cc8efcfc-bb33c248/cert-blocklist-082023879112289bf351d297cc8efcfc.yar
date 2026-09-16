import "pe"
rule cert_blocklist_082023879112289bf351d297cc8efcfc {
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
            pe.signatures[i].subject contains "STA-R TOV" and
            pe.signatures[i].serial == "08:20:23:87:91:12:28:9b:f3:51:d2:97:cc:8e:fc:fc" and
            1573430400 <= pe.signatures[i].not_after
        )
}