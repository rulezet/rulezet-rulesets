import "pe"
rule cert_blocklist_1b7b54e0dd4d7e45a0b46834de52658d {
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
            pe.signatures[i].subject contains "Xin Zhou" and
            pe.signatures[i].serial == "1b:7b:54:e0:dd:4d:7e:45:a0:b4:68:34:de:52:65:8d" and
            1476662400 <= pe.signatures[i].not_after
        )
}