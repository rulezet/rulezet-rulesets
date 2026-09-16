import "pe"
rule cert_blocklist_4743e140c05b33f0449023946bd05acb {
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
            pe.signatures[i].subject contains "STROI RENOV SARL" and
            pe.signatures[i].serial == "47:43:e1:40:c0:5b:33:f0:44:90:23:94:6b:d0:5a:cb" and
            1607644800 <= pe.signatures[i].not_after
        )
}