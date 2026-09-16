import "pe"
rule cert_blocklist_06bcb74291d96096577bdb1e165dce85 {
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
            pe.signatures[i].subject contains "Revo Security SRL" and
            pe.signatures[i].serial == "06:bc:b7:42:91:d9:60:96:57:7b:db:1e:16:5d:ce:85" and
            1637971201 <= pe.signatures[i].not_after
        )
}