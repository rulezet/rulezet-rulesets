import "pe"
rule cert_blocklist_08448bd6ee9105ae31228ea5fe496f63 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Raffaele Carnacina" and
            pe.signatures[i].serial == "08:44:8b:d6:ee:91:05:ae:31:22:8e:a5:fe:49:6f:63" and
            1445212799 <= pe.signatures[i].not_after
        )
}