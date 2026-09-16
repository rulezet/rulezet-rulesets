import "pe"
rule cert_blocklist_6967a89bcf6efef160aaeebbff376c0a {
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
            pe.signatures[i].subject contains "Chang Yucheng" and
            pe.signatures[i].serial == "69:67:a8:9b:cf:6e:fe:f1:60:aa:ee:bb:ff:37:6c:0a" and
            1451174399 <= pe.signatures[i].not_after
        )
}