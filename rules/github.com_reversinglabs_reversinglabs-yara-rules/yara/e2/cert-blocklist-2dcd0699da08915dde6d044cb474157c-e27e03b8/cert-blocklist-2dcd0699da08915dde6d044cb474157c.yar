import "pe"
rule cert_blocklist_2dcd0699da08915dde6d044cb474157c {
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
            pe.signatures[i].subject contains "VENTE DE TOUT" and
            pe.signatures[i].serial == "2d:cd:06:99:da:08:91:5d:de:6d:04:4c:b4:74:15:7c" and
            1601830010 <= pe.signatures[i].not_after
        )
}