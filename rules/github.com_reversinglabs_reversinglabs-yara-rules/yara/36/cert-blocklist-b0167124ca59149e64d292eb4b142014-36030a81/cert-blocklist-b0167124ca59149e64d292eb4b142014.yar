import "pe"
rule cert_blocklist_b0167124ca59149e64d292eb4b142014 {
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
            pe.signatures[i].subject contains "Euro May SP Z O O" and (
                pe.signatures[i].serial == "00:b0:16:71:24:ca:59:14:9e:64:d2:92:eb:4b:14:20:14" or
                pe.signatures[i].serial == "b0:16:71:24:ca:59:14:9e:64:d2:92:eb:4b:14:20:14"
            ) and
            1585267200 <= pe.signatures[i].not_after
        )
}