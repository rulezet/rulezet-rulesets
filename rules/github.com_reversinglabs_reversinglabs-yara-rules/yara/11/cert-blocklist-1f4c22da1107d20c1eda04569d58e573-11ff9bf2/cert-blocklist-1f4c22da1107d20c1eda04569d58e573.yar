import "pe"
rule cert_blocklist_1f4c22da1107d20c1eda04569d58e573 {
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
            pe.signatures[i].subject contains "PlanView, Inc." and
            pe.signatures[i].serial == "1f:4c:22:da:11:07:d2:0c:1e:da:04:56:9d:58:e5:73" and
            1366156799 <= pe.signatures[i].not_after
        )
}