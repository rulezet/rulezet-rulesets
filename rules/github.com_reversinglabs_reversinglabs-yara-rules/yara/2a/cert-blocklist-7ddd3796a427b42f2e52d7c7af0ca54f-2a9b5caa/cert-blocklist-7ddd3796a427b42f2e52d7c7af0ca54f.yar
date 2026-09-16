import "pe"
rule cert_blocklist_7ddd3796a427b42f2e52d7c7af0ca54f {
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
            pe.signatures[i].subject contains "OOO Fobos" and
            pe.signatures[i].serial == "7d:dd:37:96:a4:27:b4:2f:2e:52:d7:c7:af:0c:a5:4f" and
            1612915200 <= pe.signatures[i].not_after
        )
}