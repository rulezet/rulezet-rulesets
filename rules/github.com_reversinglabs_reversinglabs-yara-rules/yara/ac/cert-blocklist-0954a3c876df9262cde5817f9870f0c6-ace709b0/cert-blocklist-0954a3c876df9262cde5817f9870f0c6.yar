import "pe"
rule cert_blocklist_0954a3c876df9262cde5817f9870f0c6 {
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
            pe.signatures[i].subject contains "Dialer Access" and
            pe.signatures[i].serial == "09:54:a3:c8:76:df:92:62:cd:e5:81:7f:98:70:f0:c6" and
            1160438400 <= pe.signatures[i].not_after
        )
}