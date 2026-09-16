import "pe"
rule cert_blocklist_38989ec61ecdb7391ff5647f7d58ad18 {
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
            pe.signatures[i].subject contains "RotA Games ApS" and
            pe.signatures[i].serial == "38:98:9e:c6:1e:cd:b7:39:1f:f5:64:7f:7d:58:ad:18" and
            1613088000 <= pe.signatures[i].not_after
        )
}