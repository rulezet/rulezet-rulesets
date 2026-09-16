import "pe"
rule cert_blocklist_1e5efa53a14599cc82f56f0790e20b17 {
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
            pe.signatures[i].subject contains "Storeks LLC" and
            pe.signatures[i].serial == "1e:5e:fa:53:a1:45:99:cc:82:f5:6f:07:90:e2:0b:17" and
            1623196800 <= pe.signatures[i].not_after
        )
}