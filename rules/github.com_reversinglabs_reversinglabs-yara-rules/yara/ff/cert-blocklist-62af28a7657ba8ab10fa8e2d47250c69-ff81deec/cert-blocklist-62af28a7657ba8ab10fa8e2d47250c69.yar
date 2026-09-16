import "pe"
rule cert_blocklist_62af28a7657ba8ab10fa8e2d47250c69 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing GovRAT malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "AFINA Fintek" and
            pe.signatures[i].serial == "62:af:28:a7:65:7b:a8:ab:10:fa:8e:2d:47:25:0c:69" and
            1404172799 <= pe.signatures[i].not_after
        )
}