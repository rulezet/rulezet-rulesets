import "pe"
rule cert_blocklist_aff762e907f0644e76ed8a7485fb12a1 {
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
            pe.signatures[i].subject contains "Lets Start SP Z O O" and (
                pe.signatures[i].serial == "00:af:f7:62:e9:07:f0:64:4e:76:ed:8a:74:85:fb:12:a1" or
                pe.signatures[i].serial == "af:f7:62:e9:07:f0:64:4e:76:ed:8a:74:85:fb:12:a1"
            ) and
            1594882330 <= pe.signatures[i].not_after
        )
}