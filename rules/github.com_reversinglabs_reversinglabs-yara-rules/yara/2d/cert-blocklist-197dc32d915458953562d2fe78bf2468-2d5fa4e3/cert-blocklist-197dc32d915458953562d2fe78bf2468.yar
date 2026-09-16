import "pe"
rule cert_blocklist_197dc32d915458953562d2fe78bf2468 {
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
            pe.signatures[i].subject contains "Y.L. Knafo, Ltd." and
            pe.signatures[i].serial == "19:7d:c3:2d:91:54:58:95:35:62:d2:fe:78:bf:24:68" and
            1575331200 <= pe.signatures[i].not_after
        )
}