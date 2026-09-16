import "pe"
rule cert_blocklist_9a727e200ea76570 {
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
            pe.signatures[i].subject contains "Alexsandro Da Rosa - ME" and (
                pe.signatures[i].serial == "00:9a:72:7e:20:0e:a7:65:70" or
                pe.signatures[i].serial == "9a:72:7e:20:0e:a7:65:70"
            ) and
            1539056530 <= pe.signatures[i].not_after
        )
}