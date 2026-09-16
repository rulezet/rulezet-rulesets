import "pe"
rule cert_blocklist_f5f9c8f8c33e4ce84dd48fcb03ccb075 {
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
            pe.signatures[i].subject contains "Abdulkadir \\xC5\\x9Eahin" and (
                pe.signatures[i].serial == "00:f5:f9:c8:f8:c3:3e:4c:e8:4d:d4:8f:cb:03:cc:b0:75" or
                pe.signatures[i].serial == "f5:f9:c8:f8:c3:3e:4c:e8:4d:d4:8f:cb:03:cc:b0:75"
            ) and
            1545004800 <= pe.signatures[i].not_after
        )
}