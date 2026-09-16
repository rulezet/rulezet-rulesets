import "pe"
rule cert_blocklist_675129bb174a5b05e330cc09f8bbd70a {
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
            pe.signatures[i].subject contains "ALEX & CO PTY LIMITED" and
            pe.signatures[i].serial == "67:51:29:bb:17:4a:5b:05:e3:30:cc:09:f8:bb:d7:0a" and
            1565568000 <= pe.signatures[i].not_after
        )
}