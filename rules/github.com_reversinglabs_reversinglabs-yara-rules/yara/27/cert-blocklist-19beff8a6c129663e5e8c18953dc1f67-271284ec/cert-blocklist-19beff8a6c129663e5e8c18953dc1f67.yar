import "pe"
rule cert_blocklist_19beff8a6c129663e5e8c18953dc1f67 {
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
            pe.signatures[i].subject contains "CULNADY LTD LTD" and
            pe.signatures[i].serial == "19:be:ff:8a:6c:12:96:63:e5:e8:c1:89:53:dc:1f:67" and
            1608163200 <= pe.signatures[i].not_after
        )
}