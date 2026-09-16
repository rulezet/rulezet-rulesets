import "pe"
rule cert_blocklist_b649a966410f62999c939384af553919 {
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
            pe.signatures[i].subject contains "F.A.T. SARL" and (
                pe.signatures[i].serial == "00:b6:49:a9:66:41:0f:62:99:9c:93:93:84:af:55:39:19" or
                pe.signatures[i].serial == "b6:49:a9:66:41:0f:62:99:9c:93:93:84:af:55:39:19"
            ) and
            1590537600 <= pe.signatures[i].not_after
        )
}