import "pe"
rule cert_blocklist_ca646b4275406df639cf603756f63d77 {
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
            pe.signatures[i].subject contains "SHOECORP LIMITED" and (
                pe.signatures[i].serial == "00:ca:64:6b:42:75:40:6d:f6:39:cf:60:37:56:f6:3d:77" or
                pe.signatures[i].serial == "ca:64:6b:42:75:40:6d:f6:39:cf:60:37:56:f6:3d:77"
            ) and
            1605830400 <= pe.signatures[i].not_after
        )
}