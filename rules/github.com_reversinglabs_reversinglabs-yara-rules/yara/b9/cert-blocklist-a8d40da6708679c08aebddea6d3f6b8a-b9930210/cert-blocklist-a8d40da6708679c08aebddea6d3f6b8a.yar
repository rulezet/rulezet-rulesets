import "pe"
rule cert_blocklist_a8d40da6708679c08aebddea6d3f6b8a {
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
            pe.signatures[i].subject contains "VELES LTD." and (
                pe.signatures[i].serial == "00:a8:d4:0d:a6:70:86:79:c0:8a:eb:dd:ea:6d:3f:6b:8a" or
                pe.signatures[i].serial == "a8:d4:0d:a6:70:86:79:c0:8a:eb:dd:ea:6d:3f:6b:8a"
            ) and
            1547424000 <= pe.signatures[i].not_after
        )
}