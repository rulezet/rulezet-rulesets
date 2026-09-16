import "pe"
rule cert_blocklist_8223c74185add0927246f5e33ebac467 {
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
            pe.signatures[i].subject contains "TOV Virikton" and (
                pe.signatures[i].serial == "00:82:23:c7:41:85:ad:d0:92:72:46:f5:e3:3e:ba:c4:67" or
                pe.signatures[i].serial == "82:23:c7:41:85:ad:d0:92:72:46:f5:e3:3e:ba:c4:67"
            ) and
            1463616000 <= pe.signatures[i].not_after
        )
}