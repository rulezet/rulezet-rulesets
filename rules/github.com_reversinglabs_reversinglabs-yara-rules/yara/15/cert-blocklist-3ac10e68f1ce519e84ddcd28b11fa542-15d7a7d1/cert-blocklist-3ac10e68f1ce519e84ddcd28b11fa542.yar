import "pe"
rule cert_blocklist_3ac10e68f1ce519e84ddcd28b11fa542 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing Sakula malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "U-Tech IT service" and
            pe.signatures[i].serial == "3a:c1:0e:68:f1:ce:51:9e:84:dd:cd:28:b1:1f:a5:42" and
            1420156799 <= pe.signatures[i].not_after
        )
}