import "pe"
rule cert_blocklist_e4e795fd1fd25595b869ce22aa7dc49f {
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
            pe.signatures[i].subject contains "OASIS COURT LIMITED" and (
                pe.signatures[i].serial == "00:e4:e7:95:fd:1f:d2:55:95:b8:69:ce:22:aa:7d:c4:9f" or
                pe.signatures[i].serial == "e4:e7:95:fd:1f:d2:55:95:b8:69:ce:22:aa:7d:c4:9f"
            ) and
            1608508800 <= pe.signatures[i].not_after
        )
}