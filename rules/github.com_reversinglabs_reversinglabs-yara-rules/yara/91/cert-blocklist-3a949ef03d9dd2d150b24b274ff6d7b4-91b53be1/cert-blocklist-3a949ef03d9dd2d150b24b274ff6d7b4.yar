import "pe"
rule cert_blocklist_3a949ef03d9dd2d150b24b274ff6d7b4 {
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
            pe.signatures[i].subject contains "Xin Zhou" and
            pe.signatures[i].serial == "3a:94:9e:f0:3d:9d:d2:d1:50:b2:4b:27:4f:f6:d7:b4" and
            1474156800 <= pe.signatures[i].not_after
        )
}