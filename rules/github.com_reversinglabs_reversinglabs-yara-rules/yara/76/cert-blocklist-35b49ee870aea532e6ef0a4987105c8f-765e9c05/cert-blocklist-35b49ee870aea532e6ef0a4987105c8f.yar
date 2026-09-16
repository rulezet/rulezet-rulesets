import "pe"
rule cert_blocklist_35b49ee870aea532e6ef0a4987105c8f {
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
            pe.signatures[i].subject contains "Kancelaria Adwokacka Adwokat Aleksandra Krzemi\\xC5\\x84ska" and
            pe.signatures[i].serial == "35:b4:9e:e8:70:ae:a5:32:e6:ef:0a:49:87:10:5c:8f" and
            1663151018 <= pe.signatures[i].not_after
        )
}