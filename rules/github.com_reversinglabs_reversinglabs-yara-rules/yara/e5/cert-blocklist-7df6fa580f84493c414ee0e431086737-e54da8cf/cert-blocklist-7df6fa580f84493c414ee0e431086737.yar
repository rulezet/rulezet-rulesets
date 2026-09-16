import "pe"
rule cert_blocklist_7df6fa580f84493c414ee0e431086737 {
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
            pe.signatures[i].serial == "7d:f6:fa:58:0f:84:49:3c:41:4e:e0:e4:31:08:67:37" and
            1477440000 <= pe.signatures[i].not_after
        )
}