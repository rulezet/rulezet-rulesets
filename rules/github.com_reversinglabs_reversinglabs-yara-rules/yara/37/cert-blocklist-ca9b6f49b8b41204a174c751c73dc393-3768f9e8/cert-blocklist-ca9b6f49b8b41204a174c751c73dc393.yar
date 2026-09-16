import "pe"
rule cert_blocklist_ca9b6f49b8b41204a174c751c73dc393 {
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
            pe.signatures[i].subject contains "CodeDance Ltd" and (
                pe.signatures[i].serial == "00:ca:9b:6f:49:b8:b4:12:04:a1:74:c7:51:c7:3d:c3:93" or
                pe.signatures[i].serial == "ca:9b:6f:49:b8:b4:12:04:a1:74:c7:51:c7:3d:c3:93"
            ) and
            1654646400 <= pe.signatures[i].not_after
        )
}