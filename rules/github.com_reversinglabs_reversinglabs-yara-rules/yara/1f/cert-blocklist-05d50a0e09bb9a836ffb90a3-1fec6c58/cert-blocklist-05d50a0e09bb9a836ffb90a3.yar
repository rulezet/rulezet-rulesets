import "pe"
rule cert_blocklist_05d50a0e09bb9a836ffb90a3 {
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
            pe.signatures[i].subject contains "Toliz Info Tech Solutions INC." and
            pe.signatures[i].serial == "05:d5:0a:0e:09:bb:9a:83:6f:fb:90:a3" and
            1643892810 <= pe.signatures[i].not_after
        )
}