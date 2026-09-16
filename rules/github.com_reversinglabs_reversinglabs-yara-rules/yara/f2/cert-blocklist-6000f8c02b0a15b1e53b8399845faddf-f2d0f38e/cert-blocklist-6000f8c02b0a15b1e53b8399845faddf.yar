import "pe"
rule cert_blocklist_6000f8c02b0a15b1e53b8399845faddf {
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
            pe.signatures[i].subject contains "SAY LIMITED" and
            pe.signatures[i].serial == "60:00:f8:c0:2b:0a:15:b1:e5:3b:83:99:84:5f:ad:df" and
            1644278400 <= pe.signatures[i].not_after
        )
}