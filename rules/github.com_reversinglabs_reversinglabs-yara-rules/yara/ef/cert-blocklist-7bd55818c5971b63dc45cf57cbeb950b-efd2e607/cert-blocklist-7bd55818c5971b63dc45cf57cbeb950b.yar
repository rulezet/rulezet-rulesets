import "pe"
rule cert_blocklist_7bd55818c5971b63dc45cf57cbeb950b {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing Derusbi malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "XL Games Co.,Ltd." and
            pe.signatures[i].serial == "7b:d5:58:18:c5:97:1b:63:dc:45:cf:57:cb:eb:95:0b" and
            1371513599 <= pe.signatures[i].not_after
        )
}