import "pe"
rule cert_blocklist_801689896ed339237464a41a2900a969 {
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
            pe.signatures[i].subject contains "GLG Rental ApS" and (
                pe.signatures[i].serial == "00:80:16:89:89:6e:d3:39:23:74:64:a4:1a:29:00:a9:69" or
                pe.signatures[i].serial == "80:16:89:89:6e:d3:39:23:74:64:a4:1a:29:00:a9:69"
            ) and
            1615507200 <= pe.signatures[i].not_after
        )
}