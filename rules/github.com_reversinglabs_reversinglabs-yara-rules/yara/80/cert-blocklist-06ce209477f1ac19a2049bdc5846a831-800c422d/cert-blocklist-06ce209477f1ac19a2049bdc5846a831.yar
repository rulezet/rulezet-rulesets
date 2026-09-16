import "pe"
rule cert_blocklist_06ce209477f1ac19a2049bdc5846a831 {
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
            pe.signatures[i].subject contains "Select'Assistance Pro" and
            pe.signatures[i].serial == "06:ce:20:94:77:f1:ac:19:a2:04:9b:dc:58:46:a8:31" and
            1426710344 <= pe.signatures[i].not_after
        )
}