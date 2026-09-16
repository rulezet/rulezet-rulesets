import "pe"
rule cert_blocklist_fed006fbf85cd1c6ba6b4345b198e1e6 {
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
            pe.signatures[i].subject contains "LoL d.o.o." and (
                pe.signatures[i].serial == "00:fe:d0:06:fb:f8:5c:d1:c6:ba:6b:43:45:b1:98:e1:e6" or
                pe.signatures[i].serial == "fe:d0:06:fb:f8:5c:d1:c6:ba:6b:43:45:b1:98:e1:e6"
            ) and
            1614297600 <= pe.signatures[i].not_after
        )
}