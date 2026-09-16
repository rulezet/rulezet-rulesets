import "pe"
rule cert_blocklist_9faf8705a3eaef9340800cc4fd38597c {
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
            pe.signatures[i].subject contains "Tekhnokod LLC" and (
                pe.signatures[i].serial == "00:9f:af:87:05:a3:ea:ef:93:40:80:0c:c4:fd:38:59:7c" or
                pe.signatures[i].serial == "9f:af:87:05:a3:ea:ef:93:40:80:0c:c4:fd:38:59:7c"
            ) and
            1605744000 <= pe.signatures[i].not_after
        )
}