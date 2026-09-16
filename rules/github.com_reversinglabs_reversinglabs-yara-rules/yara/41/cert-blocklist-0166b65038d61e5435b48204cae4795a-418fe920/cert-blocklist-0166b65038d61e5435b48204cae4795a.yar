import "pe"
rule cert_blocklist_0166b65038d61e5435b48204cae4795a {
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
            pe.signatures[i].subject contains "TOLGA KAPLAN" and
            pe.signatures[i].serial == "01:66:b6:50:38:d6:1e:54:35:b4:82:04:ca:e4:79:5a" and
            1403999999 <= pe.signatures[i].not_after
        )
}