import "pe"
rule cert_blocklist_4fda1e121b61adeca936a6aebe079303 {
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
            pe.signatures[i].subject contains "Laizhou wanlei stone Co., LTD" and
            pe.signatures[i].serial == "4f:da:1e:12:1b:61:ad:ec:a9:36:a6:ae:be:07:93:03" and
            1310687999 <= pe.signatures[i].not_after
        )
}