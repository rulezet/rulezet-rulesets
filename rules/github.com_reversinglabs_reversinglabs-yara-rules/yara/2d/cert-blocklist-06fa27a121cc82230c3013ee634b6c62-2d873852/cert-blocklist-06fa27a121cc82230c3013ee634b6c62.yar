import "pe"
rule cert_blocklist_06fa27a121cc82230c3013ee634b6c62 {
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
            pe.signatures[i].subject contains "Zimmi Consulting Inc" and
            pe.signatures[i].serial == "06:fa:27:a1:21:cc:82:23:0c:30:13:ee:63:4b:6c:62" and
            1645142401 <= pe.signatures[i].not_after
        )
}