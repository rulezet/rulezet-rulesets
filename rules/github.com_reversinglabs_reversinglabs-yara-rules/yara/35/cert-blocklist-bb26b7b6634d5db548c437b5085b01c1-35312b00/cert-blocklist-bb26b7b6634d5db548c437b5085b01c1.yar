import "pe"
rule cert_blocklist_bb26b7b6634d5db548c437b5085b01c1 {
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
            pe.signatures[i].subject contains "OOO \"IT Mott\"" and (
                pe.signatures[i].serial == "00:bb:26:b7:b6:63:4d:5d:b5:48:c4:37:b5:08:5b:01:c1" or
                pe.signatures[i].serial == "bb:26:b7:b6:63:4d:5d:b5:48:c4:37:b5:08:5b:01:c1"
            ) and
            1591919307 <= pe.signatures[i].not_after
        )
}