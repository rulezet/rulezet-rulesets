import "pe"
rule cert_blocklist_4c8e3b1613f73542f7106f272094eb23 {
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
            pe.signatures[i].subject contains "ADD Audit" and
            pe.signatures[i].serial == "4c:8e:3b:16:13:f7:35:42:f7:10:6f:27:20:94:eb:23" and
            1472687999 <= pe.signatures[i].not_after
        )
}