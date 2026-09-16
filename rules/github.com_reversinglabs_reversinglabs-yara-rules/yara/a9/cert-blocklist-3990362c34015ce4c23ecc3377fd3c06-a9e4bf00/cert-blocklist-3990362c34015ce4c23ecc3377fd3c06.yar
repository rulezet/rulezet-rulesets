import "pe"
rule cert_blocklist_3990362c34015ce4c23ecc3377fd3c06 {
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
            pe.signatures[i].subject contains "RZOH ApS" and
            pe.signatures[i].serial == "39:90:36:2c:34:01:5c:e4:c2:3e:cc:33:77:fd:3c:06" and
            1606780800 <= pe.signatures[i].not_after
        )
}