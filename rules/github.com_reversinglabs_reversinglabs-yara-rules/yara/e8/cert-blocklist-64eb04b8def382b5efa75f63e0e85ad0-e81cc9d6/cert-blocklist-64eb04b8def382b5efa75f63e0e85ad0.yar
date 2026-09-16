import "pe"
rule cert_blocklist_64eb04b8def382b5efa75f63e0e85ad0 {
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
            pe.signatures[i].subject contains "TOV \"MARIYA\"" and
            pe.signatures[i].serial == "64:eb:04:b8:de:f3:82:b5:ef:a7:5f:63:e0:e8:5a:d0" and
            1535587200 <= pe.signatures[i].not_after
        )
}