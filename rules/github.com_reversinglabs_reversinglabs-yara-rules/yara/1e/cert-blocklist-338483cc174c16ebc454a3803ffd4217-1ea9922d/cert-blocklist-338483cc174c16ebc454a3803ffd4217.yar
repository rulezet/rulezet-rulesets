import "pe"
rule cert_blocklist_338483cc174c16ebc454a3803ffd4217 {
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
            pe.signatures[i].subject contains "Lpr:n Laatu-Ravintolat Oy" and
            pe.signatures[i].serial == "33:84:83:cc:17:4c:16:eb:c4:54:a3:80:3f:fd:42:17" and
            1635208206 <= pe.signatures[i].not_after
        )
}