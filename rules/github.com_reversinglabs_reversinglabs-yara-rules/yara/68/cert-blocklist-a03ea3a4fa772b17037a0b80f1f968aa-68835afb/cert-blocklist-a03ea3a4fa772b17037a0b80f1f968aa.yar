import "pe"
rule cert_blocklist_a03ea3a4fa772b17037a0b80f1f968aa {
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
            pe.signatures[i].subject contains "DREVOKAPITAL, s.r.o." and (
                pe.signatures[i].serial == "00:a0:3e:a3:a4:fa:77:2b:17:03:7a:0b:80:f1:f9:68:aa" or
                pe.signatures[i].serial == "a0:3e:a3:a4:fa:77:2b:17:03:7a:0b:80:f1:f9:68:aa"
            ) and
            1608076800 <= pe.signatures[i].not_after
        )
}