import "pe"
rule cert_blocklist_3112c69d460c781fd649c71e61bfec82 {
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
            pe.signatures[i].subject contains "KREATURHANDLER BJARNE ANDERSEN ApS" and
            pe.signatures[i].serial == "31:12:c6:9d:46:0c:78:1f:d6:49:c7:1e:61:bf:ec:82" and
            1614902400 <= pe.signatures[i].not_after
        )
}