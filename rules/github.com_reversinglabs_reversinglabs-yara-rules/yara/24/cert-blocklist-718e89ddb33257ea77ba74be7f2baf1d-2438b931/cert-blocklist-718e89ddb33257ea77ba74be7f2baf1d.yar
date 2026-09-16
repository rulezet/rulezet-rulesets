import "pe"
rule cert_blocklist_718e89ddb33257ea77ba74be7f2baf1d {
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
            pe.signatures[i].subject contains "Trap Capital ApS" and
            pe.signatures[i].serial == "71:8e:89:dd:b3:32:57:ea:77:ba:74:be:7f:2b:af:1d" and
            1635462927 <= pe.signatures[i].not_after
        )
}