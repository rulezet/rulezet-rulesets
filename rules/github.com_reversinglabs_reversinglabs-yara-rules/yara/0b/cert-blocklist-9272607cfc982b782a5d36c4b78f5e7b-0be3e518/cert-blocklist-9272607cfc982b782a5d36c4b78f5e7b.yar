import "pe"
rule cert_blocklist_9272607cfc982b782a5d36c4b78f5e7b {
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
            pe.signatures[i].subject contains "Rada SP Z o o" and (
                pe.signatures[i].serial == "00:92:72:60:7c:fc:98:2b:78:2a:5d:36:c4:b7:8f:5e:7b" or
                pe.signatures[i].serial == "92:72:60:7c:fc:98:2b:78:2a:5d:36:c4:b7:8f:5e:7b"
            ) and
            1605139200 <= pe.signatures[i].not_after
        )
}