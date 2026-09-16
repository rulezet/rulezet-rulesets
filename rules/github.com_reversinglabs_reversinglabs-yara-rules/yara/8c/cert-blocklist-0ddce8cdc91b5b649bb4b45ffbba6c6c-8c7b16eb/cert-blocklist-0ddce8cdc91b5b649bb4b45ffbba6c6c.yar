import "pe"
rule cert_blocklist_0ddce8cdc91b5b649bb4b45ffbba6c6c {
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
            pe.signatures[i].subject contains "SLIM DOG GROUP SP Z O O" and
            pe.signatures[i].serial == "0d:dc:e8:cd:c9:1b:5b:64:9b:b4:b4:5f:fb:ba:6c:6c" and
            1580722435 <= pe.signatures[i].not_after
        )
}