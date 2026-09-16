import "pe"
rule cert_blocklist_5389cc6286da3bfa1dc4df498bf68361 {
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
            pe.signatures[i].subject contains "Joerm.com" and
            pe.signatures[i].serial == "53:89:cc:62:86:da:3b:fa:1d:c4:df:49:8b:f6:83:61" and
            1495497600 <= pe.signatures[i].not_after
        )
}