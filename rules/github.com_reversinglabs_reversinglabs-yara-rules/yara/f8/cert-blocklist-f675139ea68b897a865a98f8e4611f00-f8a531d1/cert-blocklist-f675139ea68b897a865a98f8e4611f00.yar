import "pe"
rule cert_blocklist_f675139ea68b897a865a98f8e4611f00 {
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
            pe.signatures[i].subject contains "BS TEHNIK d.o.o." and (
                pe.signatures[i].serial == "00:f6:75:13:9e:a6:8b:89:7a:86:5a:98:f8:e4:61:1f:00" or
                pe.signatures[i].serial == "f6:75:13:9e:a6:8b:89:7a:86:5a:98:f8:e4:61:1f:00"
            ) and
            1606953600 <= pe.signatures[i].not_after
        )
}