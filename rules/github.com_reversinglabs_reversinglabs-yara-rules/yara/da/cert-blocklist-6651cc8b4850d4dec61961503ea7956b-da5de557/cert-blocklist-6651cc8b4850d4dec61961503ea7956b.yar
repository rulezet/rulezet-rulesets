import "pe"
rule cert_blocklist_6651cc8b4850d4dec61961503ea7956b {
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
            pe.signatures[i].subject contains "NUSAAPPINSTALL(APPS INSTALLER S.L.)" and
            pe.signatures[i].serial == "66:51:cc:8b:48:50:d4:de:c6:19:61:50:3e:a7:95:6b" and
            1436175828 <= pe.signatures[i].not_after
        )
}