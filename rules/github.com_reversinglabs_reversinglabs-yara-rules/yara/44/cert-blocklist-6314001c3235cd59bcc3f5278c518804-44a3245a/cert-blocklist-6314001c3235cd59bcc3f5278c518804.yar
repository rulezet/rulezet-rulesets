import "pe"
rule cert_blocklist_6314001c3235cd59bcc3f5278c518804 {
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
            pe.signatures[i].subject contains "GIE-MUTUALISTE" and
            pe.signatures[i].serial == "63:14:00:1c:32:35:cd:59:bc:c3:f5:27:8c:51:88:04" and
            1600304400 <= pe.signatures[i].not_after
        )
}