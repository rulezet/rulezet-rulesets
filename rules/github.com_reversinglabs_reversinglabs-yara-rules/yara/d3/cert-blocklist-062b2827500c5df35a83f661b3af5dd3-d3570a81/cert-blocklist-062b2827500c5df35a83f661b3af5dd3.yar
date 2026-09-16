import "pe"
rule cert_blocklist_062b2827500c5df35a83f661b3af5dd3 {
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
            pe.signatures[i].subject contains "*.eos.com" and
            pe.signatures[i].serial == "06:2b:28:27:50:0c:5d:f3:5a:83:f6:61:b3:af:5d:d3" and
            1651449600 <= pe.signatures[i].not_after
        )
}