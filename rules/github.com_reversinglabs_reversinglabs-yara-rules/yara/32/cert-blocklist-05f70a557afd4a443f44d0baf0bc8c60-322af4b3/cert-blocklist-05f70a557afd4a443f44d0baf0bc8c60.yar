import "pe"
rule cert_blocklist_05f70a557afd4a443f44d0baf0bc8c60 {
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
            pe.signatures[i].subject contains "Yu Bao" and
            pe.signatures[i].serial == "05:f7:0a:55:7a:fd:4a:44:3f:44:d0:ba:f0:bc:8c:60" and
            1477440000 <= pe.signatures[i].not_after
        )
}