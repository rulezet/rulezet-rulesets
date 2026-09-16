import "pe"
rule cert_blocklist_6aa668cd6a9de1fdd476ea8225326937 {
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
            pe.signatures[i].subject contains "BSCP LIMITED" and
            pe.signatures[i].serial == "6a:a6:68:cd:6a:9d:e1:fd:d4:76:ea:82:25:32:69:37" and
            1441583999 <= pe.signatures[i].not_after
        )
}