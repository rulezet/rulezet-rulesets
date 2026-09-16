import "pe"
rule cert_blocklist_540cea639d5d48669b7f2f64 {
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
            pe.signatures[i].subject contains "CENTR MBP LLC" and
            pe.signatures[i].serial == "54:0c:ea:63:9d:5d:48:66:9b:7f:2f:64" and
            1570871755 <= pe.signatures[i].not_after
        )
}