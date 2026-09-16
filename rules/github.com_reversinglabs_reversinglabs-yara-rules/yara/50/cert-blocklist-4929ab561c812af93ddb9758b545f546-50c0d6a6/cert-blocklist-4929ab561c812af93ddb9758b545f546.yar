import "pe"
rule cert_blocklist_4929ab561c812af93ddb9758b545f546 {
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
            pe.signatures[i].subject contains "Everything Wow s.r.o." and
            pe.signatures[i].serial == "49:29:ab:56:1c:81:2a:f9:3d:db:97:58:b5:45:f5:46" and
            1594252800 <= pe.signatures[i].not_after
        )
}