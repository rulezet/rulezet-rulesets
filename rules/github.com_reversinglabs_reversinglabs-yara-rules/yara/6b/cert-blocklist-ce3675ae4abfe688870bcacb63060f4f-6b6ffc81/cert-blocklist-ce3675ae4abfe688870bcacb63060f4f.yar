import "pe"
rule cert_blocklist_ce3675ae4abfe688870bcacb63060f4f {
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
            pe.signatures[i].subject contains "OOO \"MPS\"" and (
                pe.signatures[i].serial == "00:ce:36:75:ae:4a:bf:e6:88:87:0b:ca:cb:63:06:0f:4f" or
                pe.signatures[i].serial == "ce:36:75:ae:4a:bf:e6:88:87:0b:ca:cb:63:06:0f:4f"
            ) and
            1582675200 <= pe.signatures[i].not_after
        )
}