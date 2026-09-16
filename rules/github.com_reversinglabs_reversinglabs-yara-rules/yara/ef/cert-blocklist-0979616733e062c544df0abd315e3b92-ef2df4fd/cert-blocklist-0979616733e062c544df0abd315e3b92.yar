import "pe"
rule cert_blocklist_0979616733e062c544df0abd315e3b92 {
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
            pe.signatures[i].subject contains "Jessica Karam" and
            pe.signatures[i].serial == "09:79:61:67:33:e0:62:c5:44:df:0a:bd:31:5e:3b:92" and
            1408319999 <= pe.signatures[i].not_after
        )
}