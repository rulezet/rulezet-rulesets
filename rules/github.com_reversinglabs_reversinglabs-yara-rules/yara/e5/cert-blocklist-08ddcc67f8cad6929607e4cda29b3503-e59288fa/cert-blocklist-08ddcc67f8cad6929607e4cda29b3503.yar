import "pe"
rule cert_blocklist_08ddcc67f8cad6929607e4cda29b3503 {
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
            pe.signatures[i].subject contains "FAN-CHAI, TOV" and
            pe.signatures[i].serial == "08:dd:cc:67:f8:ca:d6:92:96:07:e4:cd:a2:9b:35:03" and
            1564310268 <= pe.signatures[i].not_after
        )
}