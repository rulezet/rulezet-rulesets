import "pe"
rule cert_blocklist_7cad9c37f7affa8f4d8229f97607e265 {
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
            pe.signatures[i].subject contains "Funbit" and
            pe.signatures[i].serial == "7c:ad:9c:37:f7:af:fa:8f:4d:82:29:f9:76:07:e2:65" and
            1122508800 <= pe.signatures[i].not_after
        )
}