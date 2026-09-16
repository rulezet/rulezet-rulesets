import "pe"
rule cert_blocklist_a7989f8be0c82d35a19e7b3dd4be30e5 {
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
            pe.signatures[i].subject contains "Instamix Limited" and (
                pe.signatures[i].serial == "00:a7:98:9f:8b:e0:c8:2d:35:a1:9e:7b:3d:d4:be:30:e5" or
                pe.signatures[i].serial == "a7:98:9f:8b:e0:c8:2d:35:a1:9e:7b:3d:d4:be:30:e5"
            ) and
            1598054400 <= pe.signatures[i].not_after
        )
}