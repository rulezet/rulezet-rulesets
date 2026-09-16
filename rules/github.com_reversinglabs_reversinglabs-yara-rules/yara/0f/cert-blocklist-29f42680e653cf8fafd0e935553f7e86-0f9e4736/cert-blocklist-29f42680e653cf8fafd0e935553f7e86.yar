import "pe"
rule cert_blocklist_29f42680e653cf8fafd0e935553f7e86 {
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
            pe.signatures[i].subject contains "Wemade Entertainment co.,Ltd" and
            pe.signatures[i].serial == "29:f4:26:80:e6:53:cf:8f:af:d0:e9:35:55:3f:7e:86" and
            1390175999 <= pe.signatures[i].not_after
        )
}