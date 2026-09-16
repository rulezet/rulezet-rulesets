import "pe"
rule cert_blocklist_08aaa069e92517f21ce67ca713f6ea63 {
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
            pe.signatures[i].subject contains "pioneersoft" and
            pe.signatures[i].serial == "08:aa:a0:69:e9:25:17:f2:1c:e6:7c:a7:13:f6:ea:63" and
            1368403200 <= pe.signatures[i].not_after
        )
}