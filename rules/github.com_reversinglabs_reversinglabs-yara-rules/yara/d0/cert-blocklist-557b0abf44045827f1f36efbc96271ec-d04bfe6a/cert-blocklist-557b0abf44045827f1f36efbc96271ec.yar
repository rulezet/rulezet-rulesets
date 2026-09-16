import "pe"
rule cert_blocklist_557b0abf44045827f1f36efbc96271ec {
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
            pe.signatures[i].subject contains "Yuanyuan Zhang" and
            pe.signatures[i].serial == "55:7b:0a:bf:44:04:58:27:f1:f3:6e:fb:c9:62:71:ec" and
            1480291200 <= pe.signatures[i].not_after
        )
}