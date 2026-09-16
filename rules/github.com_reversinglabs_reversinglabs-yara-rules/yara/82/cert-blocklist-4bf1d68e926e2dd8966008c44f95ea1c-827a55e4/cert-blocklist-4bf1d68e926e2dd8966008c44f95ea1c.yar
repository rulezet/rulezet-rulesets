import "pe"
rule cert_blocklist_4bf1d68e926e2dd8966008c44f95ea1c {
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
            pe.signatures[i].subject contains "Technical and Commercial Consulting Pvt. Ltd." and
            pe.signatures[i].serial == "4b:f1:d6:8e:92:6e:2d:d8:96:60:08:c4:4f:95:ea:1c" and
            1322092799 <= pe.signatures[i].not_after
        )
}