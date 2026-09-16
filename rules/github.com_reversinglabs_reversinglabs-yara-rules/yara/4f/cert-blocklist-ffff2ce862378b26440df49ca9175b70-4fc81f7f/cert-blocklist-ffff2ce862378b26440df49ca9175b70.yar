import "pe"
rule cert_blocklist_ffff2ce862378b26440df49ca9175b70 {
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
            pe.signatures[i].subject contains "F & A.TIM d.o.o." and (
                pe.signatures[i].serial == "00:ff:ff:2c:e8:62:37:8b:26:44:0d:f4:9c:a9:17:5b:70" or
                pe.signatures[i].serial == "ff:ff:2c:e8:62:37:8b:26:44:0d:f4:9c:a9:17:5b:70"
            ) and
            1576195200 <= pe.signatures[i].not_after
        )
}