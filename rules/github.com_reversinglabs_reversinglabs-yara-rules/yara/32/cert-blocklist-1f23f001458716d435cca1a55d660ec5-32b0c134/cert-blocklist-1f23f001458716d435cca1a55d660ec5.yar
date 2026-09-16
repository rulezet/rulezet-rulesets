import "pe"
rule cert_blocklist_1f23f001458716d435cca1a55d660ec5 {
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
            pe.signatures[i].subject contains "OOO Ringen" and
            pe.signatures[i].serial == "1f:23:f0:01:45:87:16:d4:35:cc:a1:a5:5d:66:0e:c5" and
            1603176940 <= pe.signatures[i].not_after
        )
}