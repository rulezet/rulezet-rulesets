import "pe"
rule cert_blocklist_e55be88ddbd93c423220468d430905dd {
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
            pe.signatures[i].subject contains "VALVE ACTUATION LTD" and (
                pe.signatures[i].serial == "00:e5:5b:e8:8d:db:d9:3c:42:32:20:46:8d:43:09:05:dd" or
                pe.signatures[i].serial == "e5:5b:e8:8d:db:d9:3c:42:32:20:46:8d:43:09:05:dd"
            ) and
            1637712000 <= pe.signatures[i].not_after
        )
}