import "pe"
rule cert_blocklist_2abd2eef14d480dfea9ca9fdd823cf03 {
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
            pe.signatures[i].subject contains "BE SOL d.o.o." and
            pe.signatures[i].serial == "2a:bd:2e:ef:14:d4:80:df:ea:9c:a9:fd:d8:23:cf:03" and
            1611100800 <= pe.signatures[i].not_after
        )
}