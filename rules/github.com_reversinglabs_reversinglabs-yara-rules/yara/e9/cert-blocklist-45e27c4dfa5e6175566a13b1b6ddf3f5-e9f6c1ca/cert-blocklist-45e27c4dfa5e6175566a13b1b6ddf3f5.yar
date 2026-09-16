import "pe"
rule cert_blocklist_45e27c4dfa5e6175566a13b1b6ddf3f5 {
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
            pe.signatures[i].subject contains "Selig Michael Irfan" and
            pe.signatures[i].serial == "45:e2:7c:4d:fa:5e:61:75:56:6a:13:b1:b6:dd:f3:f5" and
            1465474542 <= pe.signatures[i].not_after
        )
}