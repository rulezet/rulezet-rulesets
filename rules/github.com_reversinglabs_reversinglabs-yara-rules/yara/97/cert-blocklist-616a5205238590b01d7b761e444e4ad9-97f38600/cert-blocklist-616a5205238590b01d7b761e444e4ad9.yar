import "pe"
rule cert_blocklist_616a5205238590b01d7b761e444e4ad9 {
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
            pe.signatures[i].subject contains "Lerges" and
            pe.signatures[i].serial == "61:6a:52:05:23:85:90:b0:1d:7b:76:1e:44:4e:4a:d9" and
            1421452800 <= pe.signatures[i].not_after
        )
}