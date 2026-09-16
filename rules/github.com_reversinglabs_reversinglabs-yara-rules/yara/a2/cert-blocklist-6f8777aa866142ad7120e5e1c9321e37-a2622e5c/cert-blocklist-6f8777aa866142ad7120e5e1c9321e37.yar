import "pe"
rule cert_blocklist_6f8777aa866142ad7120e5e1c9321e37 {
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
            pe.signatures[i].subject contains "CLOUD SOFTWARE LINE CO., LTD." and
            pe.signatures[i].serial == "6f:87:77:aa:86:61:42:ad:71:20:e5:e1:c9:32:1e:37" and
            1629676800 <= pe.signatures[i].not_after
        )
}