import "pe"
rule cert_blocklist_1caa0d0dadf32a2404a75195ae47820a {
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
            pe.signatures[i].subject contains "LivePlex Corp" and
            pe.signatures[i].serial == "1c:aa:0d:0d:ad:f3:2a:24:04:a7:51:95:ae:47:82:0a" and
            1324425600 <= pe.signatures[i].not_after
        )
}