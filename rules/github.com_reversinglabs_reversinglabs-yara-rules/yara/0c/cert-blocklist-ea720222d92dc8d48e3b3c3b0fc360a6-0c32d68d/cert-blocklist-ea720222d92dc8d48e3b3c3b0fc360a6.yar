import "pe"
rule cert_blocklist_ea720222d92dc8d48e3b3c3b0fc360a6 {
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
            pe.signatures[i].subject contains "CAVANAGH NETS LIMITED" and (
                pe.signatures[i].serial == "00:ea:72:02:22:d9:2d:c8:d4:8e:3b:3c:3b:0f:c3:60:a6" or
                pe.signatures[i].serial == "ea:72:02:22:d9:2d:c8:d4:8e:3b:3c:3b:0f:c3:60:a6"
            ) and
            1608640280 <= pe.signatures[i].not_after
        )
}