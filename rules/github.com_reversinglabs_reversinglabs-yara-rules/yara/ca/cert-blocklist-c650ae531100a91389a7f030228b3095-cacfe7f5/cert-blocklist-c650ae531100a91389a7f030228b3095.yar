import "pe"
rule cert_blocklist_c650ae531100a91389a7f030228b3095 {
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
            pe.signatures[i].subject contains "POKEROWA STRUNA SP Z O O" and (
                pe.signatures[i].serial == "00:c6:50:ae:53:11:00:a9:13:89:a7:f0:30:22:8b:30:95" or
                pe.signatures[i].serial == "c6:50:ae:53:11:00:a9:13:89:a7:f0:30:22:8b:30:95"
            ) and
            1606089600 <= pe.signatures[i].not_after
        )
}