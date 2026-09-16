import "pe"
rule cert_blocklist_3e39c2ccc494438bb8c2560f {
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
            pe.signatures[i].subject contains "VANKY TECHNOLOGY LIMITED" and
            pe.signatures[i].serial == "3e:39:c2:cc:c4:94:43:8b:b8:c2:56:0f" and
            1466142876 <= pe.signatures[i].not_after
        )
}