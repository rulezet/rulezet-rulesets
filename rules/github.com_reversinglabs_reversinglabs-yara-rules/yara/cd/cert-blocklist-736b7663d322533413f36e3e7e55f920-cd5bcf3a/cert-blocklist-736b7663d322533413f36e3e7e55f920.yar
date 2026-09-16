import "pe"
rule cert_blocklist_736b7663d322533413f36e3e7e55f920 {
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
            pe.signatures[i].subject contains "Net Technology" and
            pe.signatures[i].serial == "73:6b:76:63:d3:22:53:34:13:f3:6e:3e:7e:55:f9:20" and
            1159488000 <= pe.signatures[i].not_after
        )
}