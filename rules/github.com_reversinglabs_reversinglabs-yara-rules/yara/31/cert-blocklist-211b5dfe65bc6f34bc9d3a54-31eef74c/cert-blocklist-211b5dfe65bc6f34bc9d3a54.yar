import "pe"
rule cert_blocklist_211b5dfe65bc6f34bc9d3a54 {
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
            pe.signatures[i].subject contains "RAFO TECHNOLOGY INC" and
            pe.signatures[i].serial == "21:1b:5d:fe:65:bc:6f:34:bc:9d:3a:54" and
            1526717931 <= pe.signatures[i].not_after
        )
}