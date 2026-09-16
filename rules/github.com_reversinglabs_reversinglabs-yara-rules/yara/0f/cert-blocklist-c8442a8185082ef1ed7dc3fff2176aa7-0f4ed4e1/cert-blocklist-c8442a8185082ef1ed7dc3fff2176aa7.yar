import "pe"
rule cert_blocklist_c8442a8185082ef1ed7dc3fff2176aa7 {
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
            pe.signatures[i].subject contains "Ambidekstr LLC" and (
                pe.signatures[i].serial == "00:c8:44:2a:81:85:08:2e:f1:ed:7d:c3:ff:f2:17:6a:a7" or
                pe.signatures[i].serial == "c8:44:2a:81:85:08:2e:f1:ed:7d:c3:ff:f2:17:6a:a7"
            ) and
            1616976000 <= pe.signatures[i].not_after
        )
}