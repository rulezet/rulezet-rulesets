import "pe"
rule cert_blocklist_0fd2b19a941b7009cc728a37cb1b10b9 {
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
            pe.signatures[i].subject contains "BEAR AND CILLA LTD" and
            pe.signatures[i].serial == "0f:d2:b1:9a:94:1b:70:09:cc:72:8a:37:cb:1b:10:b9" and
            1560470400 <= pe.signatures[i].not_after
        )
}