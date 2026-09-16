import "pe"
rule cert_blocklist_34ec9565805f34204c6966fb81e36ba1 {
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
            pe.signatures[i].serial == "34:ec:95:65:80:5f:34:20:4c:69:66:fb:81:e3:6b:a1" and
            1476921600 <= pe.signatures[i].not_after
        )
}