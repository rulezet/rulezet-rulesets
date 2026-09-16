import "pe"
rule cert_blocklist_e04a344b397f752a45b128a594a3d6b5 {
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
            pe.signatures[i].subject contains "Highweb Ireland Operations Limited" and (
                pe.signatures[i].serial == "00:e0:4a:34:4b:39:7f:75:2a:45:b1:28:a5:94:a3:d6:b5" or
                pe.signatures[i].serial == "e0:4a:34:4b:39:7f:75:2a:45:b1:28:a5:94:a3:d6:b5"
            ) and
            1597708800 <= pe.signatures[i].not_after
        )
}