import "pe"
rule cert_blocklist_285eccbd1d0000e640b84307ef88cd9f {
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
            pe.signatures[i].subject contains "DRAGON BUSINESS EQUIPMENT LIMITED" and
            pe.signatures[i].serial == "28:5e:cc:bd:1d:00:00:e6:40:b8:43:07:ef:88:cd:9f" and
            1611619200 <= pe.signatures[i].not_after
        )
}