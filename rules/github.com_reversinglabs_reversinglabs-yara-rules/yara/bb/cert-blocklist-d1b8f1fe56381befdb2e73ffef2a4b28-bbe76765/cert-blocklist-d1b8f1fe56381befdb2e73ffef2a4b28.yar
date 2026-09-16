import "pe"
rule cert_blocklist_d1b8f1fe56381befdb2e73ffef2a4b28 {
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
            pe.signatures[i].subject contains "Sein\\xC3\\xA4joen Squash ja Bowling Oy" and (
                pe.signatures[i].serial == "00:d1:b8:f1:fe:56:38:1b:ef:db:2e:73:ff:ef:2a:4b:28" or
                pe.signatures[i].serial == "d1:b8:f1:fe:56:38:1b:ef:db:2e:73:ff:ef:2a:4b:28"
            ) and
            1617667200 <= pe.signatures[i].not_after
        )
}