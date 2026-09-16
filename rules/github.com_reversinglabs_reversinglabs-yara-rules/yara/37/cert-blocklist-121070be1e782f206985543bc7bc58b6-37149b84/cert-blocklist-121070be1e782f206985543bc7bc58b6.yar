import "pe"
rule cert_blocklist_121070be1e782f206985543bc7bc58b6 {
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
            pe.signatures[i].subject contains "Prod Can Holdings Inc." and
            pe.signatures[i].serial == "12:10:70:be:1e:78:2f:20:69:85:54:3b:c7:bc:58:b6" and
            1647820800 <= pe.signatures[i].not_after
        )
}