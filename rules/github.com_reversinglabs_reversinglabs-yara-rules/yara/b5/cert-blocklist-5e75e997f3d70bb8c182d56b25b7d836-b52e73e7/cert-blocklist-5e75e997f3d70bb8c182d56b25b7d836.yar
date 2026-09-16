import "pe"
rule cert_blocklist_5e75e997f3d70bb8c182d56b25b7d836 {
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
            pe.signatures[i].subject contains "Primetech Ltd." and
            pe.signatures[i].serial == "5e:75:e9:97:f3:d7:0b:b8:c1:82:d5:6b:25:b7:d8:36" and
            1324252800 <= pe.signatures[i].not_after
        )
}