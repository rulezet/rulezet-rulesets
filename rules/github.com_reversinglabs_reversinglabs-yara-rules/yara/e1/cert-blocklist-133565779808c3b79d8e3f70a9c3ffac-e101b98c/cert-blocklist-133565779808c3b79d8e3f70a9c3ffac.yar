import "pe"
rule cert_blocklist_133565779808c3b79d8e3f70a9c3ffac {
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
            pe.signatures[i].subject contains "OOO Istok" and
            pe.signatures[i].serial == "13:35:65:77:98:08:c3:b7:9d:8e:3f:70:a9:c3:ff:ac" and
            1605019819 <= pe.signatures[i].not_after
        )
}