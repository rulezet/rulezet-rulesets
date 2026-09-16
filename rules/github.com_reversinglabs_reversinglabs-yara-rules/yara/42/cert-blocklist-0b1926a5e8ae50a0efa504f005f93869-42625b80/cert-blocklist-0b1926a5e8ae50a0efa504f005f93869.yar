import "pe"
rule cert_blocklist_0b1926a5e8ae50a0efa504f005f93869 {
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
            pe.signatures[i].subject contains "Nordkod LLC" and
            pe.signatures[i].serial == "0b:19:26:a5:e8:ae:50:a0:ef:a5:04:f0:05:f9:38:69" and
            1600650000 <= pe.signatures[i].not_after
        )
}