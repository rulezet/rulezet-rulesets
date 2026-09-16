import "pe"
rule cert_blocklist_961cecb0227845317549e9343a980e91 {
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
            pe.signatures[i].subject contains "AmiraCo Oy" and (
                pe.signatures[i].serial == "00:96:1c:ec:b0:22:78:45:31:75:49:e9:34:3a:98:0e:91" or
                pe.signatures[i].serial == "96:1c:ec:b0:22:78:45:31:75:49:e9:34:3a:98:0e:91"
            ) and
            1615248000 <= pe.signatures[i].not_after
        )
}