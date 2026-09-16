import "pe"
rule cert_blocklist_22e2a66e63b8cb4ec6989bf7 {
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
            pe.signatures[i].subject contains "Sivi Technology Limited" and
            pe.signatures[i].serial == "22:e2:a6:6e:63:b8:cb:4e:c6:98:9b:f7" and
            1466995365 <= pe.signatures[i].not_after
        )
}