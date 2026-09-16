import "pe"
rule cert_blocklist_0813ee9b7b9d7c46001d6bc8784df1dd {
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
            pe.signatures[i].subject contains "Les Garcons s'habillent" and
            pe.signatures[i].serial == "08:13:ee:9b:7b:9d:7c:46:00:1d:6b:c8:78:4d:f1:dd" and
            1334707199 <= pe.signatures[i].not_after
        )
}