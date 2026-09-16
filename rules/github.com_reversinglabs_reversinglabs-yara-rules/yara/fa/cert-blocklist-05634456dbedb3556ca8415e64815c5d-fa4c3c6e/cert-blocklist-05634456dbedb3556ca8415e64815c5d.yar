import "pe"
rule cert_blocklist_05634456dbedb3556ca8415e64815c5d {
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
            pe.signatures[i].subject contains "Walden Intertech Inc." and
            pe.signatures[i].serial == "05:63:44:56:db:ed:b3:55:6c:a8:41:5e:64:81:5c:5d" and
            1648425600 <= pe.signatures[i].not_after
        )
}