import "pe"
rule cert_blocklist_3bcaed3ef678f2f9bf38d09e149b8d70 {
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
            pe.signatures[i].subject contains "StarY Media Inc." and
            pe.signatures[i].serial == "3b:ca:ed:3e:f6:78:f2:f9:bf:38:d0:9e:14:9b:8d:70" and
            1599091200 <= pe.signatures[i].not_after
        )
}