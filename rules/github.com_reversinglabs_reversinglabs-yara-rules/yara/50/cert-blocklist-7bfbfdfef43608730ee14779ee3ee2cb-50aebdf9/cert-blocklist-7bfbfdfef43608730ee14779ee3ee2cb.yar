import "pe"
rule cert_blocklist_7bfbfdfef43608730ee14779ee3ee2cb {
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
            pe.signatures[i].subject contains "CSTech Software Inc." and
            pe.signatures[i].serial == "7b:fb:fd:fe:f4:36:08:73:0e:e1:47:79:ee:3e:e2:cb" and
            1590537600 <= pe.signatures[i].not_after
        )
}