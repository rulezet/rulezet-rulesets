import "pe"
rule cert_blocklist_0c501b8b113209c96c8119cf7a6b8b79 {
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
            pe.signatures[i].subject contains "Yuanyuan Zhang" and
            pe.signatures[i].serial == "0c:50:1b:8b:11:32:09:c9:6c:81:19:cf:7a:6b:8b:79" and
            1474329600 <= pe.signatures[i].not_after
        )
}