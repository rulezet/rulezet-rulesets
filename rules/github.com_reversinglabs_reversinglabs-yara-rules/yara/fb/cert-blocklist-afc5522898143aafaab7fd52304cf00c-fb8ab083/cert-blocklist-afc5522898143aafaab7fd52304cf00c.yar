import "pe"
rule cert_blocklist_afc5522898143aafaab7fd52304cf00c {
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
            pe.signatures[i].subject contains "YAN CHING LIMITED" and (
                pe.signatures[i].serial == "00:af:c5:52:28:98:14:3a:af:aa:b7:fd:52:30:4c:f0:0c" or
                pe.signatures[i].serial == "af:c5:52:28:98:14:3a:af:aa:b7:fd:52:30:4c:f0:0c"
            ) and
            1622419200 <= pe.signatures[i].not_after
        )
}