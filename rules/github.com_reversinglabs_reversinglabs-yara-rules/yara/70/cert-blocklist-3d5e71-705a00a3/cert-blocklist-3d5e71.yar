import "pe"
rule cert_blocklist_3d5e71 {
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
            pe.signatures[i].subject contains "OF.PL sp. z o.o." and
            pe.signatures[i].serial == "3d:5e:71" and
            1066997730 <= pe.signatures[i].not_after
        )
}