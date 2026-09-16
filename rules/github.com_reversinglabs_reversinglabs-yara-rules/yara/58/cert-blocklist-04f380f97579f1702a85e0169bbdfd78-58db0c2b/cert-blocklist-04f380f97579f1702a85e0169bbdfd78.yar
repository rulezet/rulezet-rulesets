import "pe"
rule cert_blocklist_04f380f97579f1702a85e0169bbdfd78 {
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
            pe.signatures[i].subject contains "GRANIFLOR" and
            pe.signatures[i].serial == "04:f3:80:f9:75:79:f1:70:2a:85:e0:16:9b:bd:fd:78" and
            1454889599 <= pe.signatures[i].not_after
        )
}