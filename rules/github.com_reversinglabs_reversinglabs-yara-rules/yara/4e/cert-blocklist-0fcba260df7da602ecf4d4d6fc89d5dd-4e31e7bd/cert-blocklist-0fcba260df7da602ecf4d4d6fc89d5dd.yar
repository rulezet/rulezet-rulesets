import "pe"
rule cert_blocklist_0fcba260df7da602ecf4d4d6fc89d5dd {
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
            pe.signatures[i].subject contains "Gold Stroy SP Z O O" and
            pe.signatures[i].serial == "0f:cb:a2:60:df:7d:a6:02:ec:f4:d4:d6:fc:89:d5:dd" and
            1593388801 <= pe.signatures[i].not_after
        )
}