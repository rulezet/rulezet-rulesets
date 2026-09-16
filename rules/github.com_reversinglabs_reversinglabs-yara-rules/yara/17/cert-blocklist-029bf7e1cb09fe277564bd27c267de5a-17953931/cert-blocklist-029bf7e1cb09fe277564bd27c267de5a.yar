import "pe"
rule cert_blocklist_029bf7e1cb09fe277564bd27c267de5a {
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
            pe.signatures[i].subject contains "SAMOYAJ LIMITED" and
            pe.signatures[i].serial == "02:9b:f7:e1:cb:09:fe:27:75:64:bd:27:c2:67:de:5a" and
            1637712001 <= pe.signatures[i].not_after
        )
}