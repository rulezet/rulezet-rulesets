import "pe"
rule cert_blocklist_97df46acb26b7c81a13cc467b47688c8 {
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
            pe.signatures[i].subject contains "Information Civilized System Oy" and (
                pe.signatures[i].serial == "00:97:df:46:ac:b2:6b:7c:81:a1:3c:c4:67:b4:76:88:c8" or
                pe.signatures[i].serial == "97:df:46:ac:b2:6b:7c:81:a1:3c:c4:67:b4:76:88:c8"
            ) and
            1602636910 <= pe.signatures[i].not_after
        )
}