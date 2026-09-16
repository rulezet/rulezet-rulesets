import "pe"
rule cert_blocklist_c79f817f082986bef3209f6723c8da97 {
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
            pe.signatures[i].subject contains "Al-Faris group d.o.o." and (
                pe.signatures[i].serial == "00:c7:9f:81:7f:08:29:86:be:f3:20:9f:67:23:c8:da:97" or
                pe.signatures[i].serial == "c7:9f:81:7f:08:29:86:be:f3:20:9f:67:23:c8:da:97"
            ) and
            1616371200 <= pe.signatures[i].not_after
        )
}