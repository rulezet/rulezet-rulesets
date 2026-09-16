import "pe"
rule cert_blocklist_3e1656dfcaacfed7c2d2564355698aa3 {
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
            pe.signatures[i].subject contains "John W.Richard" and
            pe.signatures[i].serial == "3e:16:56:df:ca:ac:fe:d7:c2:d2:56:43:55:69:8a:a3" and
            1385251199 <= pe.signatures[i].not_after
        )
}