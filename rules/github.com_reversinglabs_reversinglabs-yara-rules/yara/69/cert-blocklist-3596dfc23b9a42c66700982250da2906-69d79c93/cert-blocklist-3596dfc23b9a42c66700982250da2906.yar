import "pe"
rule cert_blocklist_3596dfc23b9a42c66700982250da2906 {
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
            pe.signatures[i].subject contains "Open Source Developer, Song WU" and
            pe.signatures[i].serial == "35:96:df:c2:3b:9a:42:c6:67:00:98:22:50:da:29:06" and
            1397219344 <= pe.signatures[i].not_after
        )
}