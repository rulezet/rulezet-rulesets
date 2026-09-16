import "pe"
rule cert_blocklist_5e15205f180442cc6c3c0f03e1a33d9f {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Ziber Ltd" and
            pe.signatures[i].serial == "5e:15:20:5f:18:04:42:cc:6c:3c:0f:03:e1:a3:3d:9f" and
            1498607999 <= pe.signatures[i].not_after
        )
}