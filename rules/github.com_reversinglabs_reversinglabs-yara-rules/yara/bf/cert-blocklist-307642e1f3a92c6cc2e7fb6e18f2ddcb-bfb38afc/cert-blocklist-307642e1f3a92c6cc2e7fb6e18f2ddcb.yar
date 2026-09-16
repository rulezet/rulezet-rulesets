import "pe"
rule cert_blocklist_307642e1f3a92c6cc2e7fb6e18f2ddcb {
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
            pe.signatures[i].subject contains "IBM" and
            pe.signatures[i].serial == "30:76:42:e1:f3:a9:2c:6c:c2:e7:fb:6e:18:f2:dd:cb" and
            1500422400 <= pe.signatures[i].not_after
        )
}