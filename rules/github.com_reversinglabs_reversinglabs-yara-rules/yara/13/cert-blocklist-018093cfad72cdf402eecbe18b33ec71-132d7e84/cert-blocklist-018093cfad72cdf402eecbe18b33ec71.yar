import "pe"
rule cert_blocklist_018093cfad72cdf402eecbe18b33ec71 {
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
            pe.signatures[i].subject contains "FAT11 d.o.o." and 
            pe.signatures[i].serial == "01:80:93:cf:ad:72:cd:f4:02:ee:cb:e1:8b:33:ec:71" and
            1602000390 <= pe.signatures[i].not_after
        )
}