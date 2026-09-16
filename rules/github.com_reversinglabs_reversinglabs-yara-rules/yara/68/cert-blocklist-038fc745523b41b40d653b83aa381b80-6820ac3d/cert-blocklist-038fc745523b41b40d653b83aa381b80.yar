import "pe"
rule cert_blocklist_038fc745523b41b40d653b83aa381b80 {
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
            pe.signatures[i].subject contains "OOO Optima" and
            pe.signatures[i].serial == "03:8f:c7:45:52:3b:41:b4:0d:65:3b:83:aa:38:1b:80" and
            1606143708 <= pe.signatures[i].not_after
        )
}