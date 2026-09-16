import "pe"
rule cert_blocklist_485e4626c32493c16283cfd9e30d17ad {
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
            pe.signatures[i].serial == "48:5e:46:26:c3:24:93:c1:62:83:cf:d9:e3:0d:17:ad" and
            1473292800 <= pe.signatures[i].not_after
        )
}