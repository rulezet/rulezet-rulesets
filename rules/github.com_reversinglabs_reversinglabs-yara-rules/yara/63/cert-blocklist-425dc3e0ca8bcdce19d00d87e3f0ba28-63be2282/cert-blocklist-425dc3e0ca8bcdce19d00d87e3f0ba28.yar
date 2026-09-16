import "pe"
rule cert_blocklist_425dc3e0ca8bcdce19d00d87e3f0ba28 {
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
            pe.signatures[i].subject contains "Protover LLC" and
            pe.signatures[i].serial == "42:5d:c3:e0:ca:8b:cd:ce:19:d0:0d:87:e3:f0:ba:28" and
            1621900800 <= pe.signatures[i].not_after
        )
}