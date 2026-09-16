import "pe"
rule cert_blocklist_09fb28 {
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
            pe.signatures[i].subject contains "New Dial spa" and
            pe.signatures[i].serial == "09:fb:28" and
            1046968418 <= pe.signatures[i].not_after
        )
}