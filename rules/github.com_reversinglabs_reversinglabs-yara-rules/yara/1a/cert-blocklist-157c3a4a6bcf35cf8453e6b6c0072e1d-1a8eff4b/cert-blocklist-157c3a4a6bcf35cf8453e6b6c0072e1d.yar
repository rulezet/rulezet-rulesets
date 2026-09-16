import "pe"
rule cert_blocklist_157c3a4a6bcf35cf8453e6b6c0072e1d {
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
            pe.signatures[i].subject contains "Favorite-III" and
            pe.signatures[i].serial == "15:7c:3a:4a:6b:cf:35:cf:84:53:e6:b6:c0:07:2e:1d" and
            1404172799 <= pe.signatures[i].not_after
        )
}