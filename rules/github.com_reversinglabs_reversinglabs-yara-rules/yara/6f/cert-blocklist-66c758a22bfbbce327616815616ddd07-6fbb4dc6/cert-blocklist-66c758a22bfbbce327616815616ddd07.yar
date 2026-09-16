import "pe"
rule cert_blocklist_66c758a22bfbbce327616815616ddd07 {
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
            pe.signatures[i].subject contains "TIM Konstrakshn, TOV" and
            pe.signatures[i].serial == "66:c7:58:a2:2b:fb:bc:e3:27:61:68:15:61:6d:dd:07" and
            1469404800 <= pe.signatures[i].not_after
        )
}