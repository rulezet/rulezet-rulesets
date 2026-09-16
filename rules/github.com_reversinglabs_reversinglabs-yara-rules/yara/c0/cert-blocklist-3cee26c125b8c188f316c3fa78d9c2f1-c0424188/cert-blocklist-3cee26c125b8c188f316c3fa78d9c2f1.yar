import "pe"
rule cert_blocklist_3cee26c125b8c188f316c3fa78d9c2f1 {
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
            pe.signatures[i].subject contains "Bitubit LLC" and
            pe.signatures[i].serial == "3c:ee:26:c1:25:b8:c1:88:f3:16:c3:fa:78:d9:c2:f1" and
            1606435200 <= pe.signatures[i].not_after
        )
}