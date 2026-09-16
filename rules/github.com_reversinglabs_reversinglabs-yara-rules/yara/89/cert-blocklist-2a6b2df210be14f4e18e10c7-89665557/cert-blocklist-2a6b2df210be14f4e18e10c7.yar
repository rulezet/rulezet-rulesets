import "pe"
rule cert_blocklist_2a6b2df210be14f4e18e10c7 {
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
            pe.signatures[i].subject contains "VANKY TECHNOLOGY LIMITED" and
            pe.signatures[i].serial == "2a:6b:2d:f2:10:be:14:f4:e1:8e:10:c7" and
            1472095404 <= pe.signatures[i].not_after
        )
}