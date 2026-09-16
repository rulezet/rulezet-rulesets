import "pe"
rule cert_blocklist_634e16e38f12e9a71aca08e4c6b2dbb9 {
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
            pe.signatures[i].subject contains "AUTO RESPONSE LTD CYF" and
            pe.signatures[i].serial == "63:4e:16:e3:8f:12:e9:a7:1a:ca:08:e4:c6:b2:db:b9" and
            1616112000 <= pe.signatures[i].not_after
        )
}