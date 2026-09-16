import "pe"
rule cert_blocklist_dd9e9e1d7c573714e3f567c5380ae6d0 {
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
            pe.signatures[i].subject contains "CREA&COM d.o.o." and (
                pe.signatures[i].serial == "00:dd:9e:9e:1d:7c:57:37:14:e3:f5:67:c5:38:0a:e6:d0" or
                pe.signatures[i].serial == "dd:9e:9e:1d:7c:57:37:14:e3:f5:67:c5:38:0a:e6:d0"
            ) and
            1575849600 <= pe.signatures[i].not_after
        )
}