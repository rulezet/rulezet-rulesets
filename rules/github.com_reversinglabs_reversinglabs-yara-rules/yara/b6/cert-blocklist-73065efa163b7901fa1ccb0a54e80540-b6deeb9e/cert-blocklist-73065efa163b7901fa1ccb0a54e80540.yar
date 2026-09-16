import "pe"
rule cert_blocklist_73065efa163b7901fa1ccb0a54e80540 {
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
            pe.signatures[i].subject contains "SOVA CONSULTANCY LTD" and
            pe.signatures[i].serial == "73:06:5e:fa:16:3b:79:01:fa:1c:cb:0a:54:e8:05:40" and
            1548115200 <= pe.signatures[i].not_after
        )
}