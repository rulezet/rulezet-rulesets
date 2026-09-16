import "pe"
rule cert_blocklist_32119925a6ce4710aecc4006c28e749f {
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
            pe.signatures[i].subject contains "Maxiol" and
            pe.signatures[i].serial == "32:11:99:25:a6:ce:47:10:ae:cc:40:06:c2:8e:74:9f" and
            1592438400 <= pe.signatures[i].not_after
        )
}