import "pe"
rule cert_blocklist_54a170102461fdc967acfafe4bbbc7f0 {
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
            pe.signatures[i].subject contains "Yu Bao" and
            pe.signatures[i].serial == "54:a1:70:10:24:61:fd:c9:67:ac:fa:fe:4b:bb:c7:f0" and
            1476748800 <= pe.signatures[i].not_after
        )
}