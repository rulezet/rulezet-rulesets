import "pe"
rule cert_blocklist_d4ef1ab6ab5d3cb35e4efb7984def7a2 {
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
            pe.signatures[i].subject contains "REIGN BROS ApS" and (
                pe.signatures[i].serial == "00:d4:ef:1a:b6:ab:5d:3c:b3:5e:4e:fb:79:84:de:f7:a2" or
                pe.signatures[i].serial == "d4:ef:1a:b6:ab:5d:3c:b3:5e:4e:fb:79:84:de:f7:a2"
            ) and
            1611187200 <= pe.signatures[i].not_after
        )
}