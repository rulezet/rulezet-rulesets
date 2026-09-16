import "pe"
rule cert_blocklist_65eae6c98111dc40bf4f962bf27227f2 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing GovRAT malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Open Source Developer, BHARATH KUCHANGI" and
            pe.signatures[i].serial == "65:ea:e6:c9:81:11:dc:40:bf:4f:96:2b:f2:72:27:f2" and
            1404172799 <= pe.signatures[i].not_after
        )
}