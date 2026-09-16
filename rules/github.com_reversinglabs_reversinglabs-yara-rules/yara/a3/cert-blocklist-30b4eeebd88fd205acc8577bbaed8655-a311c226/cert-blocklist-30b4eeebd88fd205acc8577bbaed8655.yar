import "pe"
rule cert_blocklist_30b4eeebd88fd205acc8577bbaed8655 {
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
            pe.signatures[i].subject contains "Enforcer Srl" and
            pe.signatures[i].serial == "30:b4:ee:eb:d8:8f:d2:05:ac:c8:57:7b:ba:ed:86:55" and
            1646179200 <= pe.signatures[i].not_after
        )
}