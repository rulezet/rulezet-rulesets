import "pe"
rule cert_blocklist_0a77cf3ba49b64e6cbe5fb4a6a6aacc6 {
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
            pe.signatures[i].subject contains "I.ST.SAN. Srl" and
            pe.signatures[i].serial == "0a:77:cf:3b:a4:9b:64:e6:cb:e5:fb:4a:6a:6a:ac:c6" and
            1371081599 <= pe.signatures[i].not_after
        )
}