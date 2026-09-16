import "pe"
rule cert_blocklist_3e9d26dcf703ca3b140d7e7ad48312e2 {
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
            pe.signatures[i].subject contains "Dong Qian" and
            pe.signatures[i].serial == "3e:9d:26:dc:f7:03:ca:3b:14:0d:7e:7a:d4:83:12:e2" and
            1440580240 <= pe.signatures[i].not_after
        )
}