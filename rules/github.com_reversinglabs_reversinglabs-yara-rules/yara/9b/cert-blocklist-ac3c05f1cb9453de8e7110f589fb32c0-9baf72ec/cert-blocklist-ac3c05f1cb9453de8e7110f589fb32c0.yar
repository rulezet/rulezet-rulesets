import "pe"
rule cert_blocklist_ac3c05f1cb9453de8e7110f589fb32c0 {
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
            pe.signatures[i].subject contains "TRAIN BUILDING TEAM s.r.o." and (
                pe.signatures[i].serial == "00:ac:3c:05:f1:cb:94:53:de:8e:71:10:f5:89:fb:32:c0" or
                pe.signatures[i].serial == "ac:3c:05:f1:cb:94:53:de:8e:71:10:f5:89:fb:32:c0"
            ) and
            1635854205 <= pe.signatures[i].not_after
        )
}