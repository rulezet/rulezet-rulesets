import "pe"
rule cert_blocklist_7ebcb54b7e0e6410b28610de0743d4dd {
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
            pe.signatures[i].subject contains "SIA \"MWorx\"" and
            pe.signatures[i].serial == "7e:bc:b5:4b:7e:0e:64:10:b2:86:10:de:07:43:d4:dd" and
            1625616000 <= pe.signatures[i].not_after
        )
}