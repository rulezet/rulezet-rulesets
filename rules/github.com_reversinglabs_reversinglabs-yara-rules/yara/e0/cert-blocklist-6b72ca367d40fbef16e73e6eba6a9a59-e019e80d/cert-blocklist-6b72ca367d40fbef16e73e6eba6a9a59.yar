import "pe"
rule cert_blocklist_6b72ca367d40fbef16e73e6eba6a9a59 {
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
            pe.signatures[i].serial == "6b:72:ca:36:7d:40:fb:ef:16:e7:3e:6e:ba:6a:9a:59" and
            1476748800 <= pe.signatures[i].not_after
        )
}