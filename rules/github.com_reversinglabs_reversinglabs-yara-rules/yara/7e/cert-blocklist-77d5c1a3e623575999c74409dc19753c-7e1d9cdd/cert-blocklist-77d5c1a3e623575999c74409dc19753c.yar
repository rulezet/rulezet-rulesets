import "pe"
rule cert_blocklist_77d5c1a3e623575999c74409dc19753c {
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
            pe.signatures[i].serial == "77:d5:c1:a3:e6:23:57:59:99:c7:44:09:dc:19:75:3c" and
            1475884800 <= pe.signatures[i].not_after
        )
}