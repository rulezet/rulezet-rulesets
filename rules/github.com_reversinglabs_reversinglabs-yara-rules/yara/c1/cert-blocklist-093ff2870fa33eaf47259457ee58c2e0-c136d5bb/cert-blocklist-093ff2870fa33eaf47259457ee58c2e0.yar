import "pe"
rule cert_blocklist_093ff2870fa33eaf47259457ee58c2e0 {
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
            pe.signatures[i].subject contains "AEEPZ Limited" and
            pe.signatures[i].serial == "09:3f:f2:87:0f:a3:3e:af:47:25:94:57:ee:58:c2:e0" and
            1503532800 <= pe.signatures[i].not_after
        )
}