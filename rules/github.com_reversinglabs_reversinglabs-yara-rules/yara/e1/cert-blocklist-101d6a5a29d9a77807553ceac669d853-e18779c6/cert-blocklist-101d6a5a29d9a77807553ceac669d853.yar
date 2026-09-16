import "pe"
rule cert_blocklist_101d6a5a29d9a77807553ceac669d853 {
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
            pe.signatures[i].subject contains "BIC GROUP LIMITED" and
            pe.signatures[i].serial == "10:1d:6a:5a:29:d9:a7:78:07:55:3c:ea:c6:69:d8:53" and
            1646352000 <= pe.signatures[i].not_after
        )
}