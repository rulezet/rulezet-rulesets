import "pe"
rule cert_blocklist_15c5af15afecf1c900cbab0ca9165629 {
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
            pe.signatures[i].subject contains "Kompaniya Auttek" and
            pe.signatures[i].serial == "15:c5:af:15:af:ec:f1:c9:00:cb:ab:0c:a9:16:56:29" and
            1586091840 <= pe.signatures[i].not_after
        )
}