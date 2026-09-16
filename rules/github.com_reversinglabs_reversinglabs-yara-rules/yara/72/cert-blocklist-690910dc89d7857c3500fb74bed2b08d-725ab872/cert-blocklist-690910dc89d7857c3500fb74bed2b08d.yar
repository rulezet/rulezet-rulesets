import "pe"
rule cert_blocklist_690910dc89d7857c3500fb74bed2b08d {
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
            pe.signatures[i].subject contains "OLIMP STROI, OOO" and
            pe.signatures[i].serial == "69:09:10:dc:89:d7:85:7c:35:00:fb:74:be:d2:b0:8d" and
            1597276800 <= pe.signatures[i].not_after
        )
}