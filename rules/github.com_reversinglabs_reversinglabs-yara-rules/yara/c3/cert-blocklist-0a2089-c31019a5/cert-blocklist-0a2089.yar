import "pe"
rule cert_blocklist_0a2089 {
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
            pe.signatures[i].subject contains "RocketMedia S.r.l." and
            pe.signatures[i].serial == "0a:20:89" and
            1050073884 <= pe.signatures[i].not_after
        )
}