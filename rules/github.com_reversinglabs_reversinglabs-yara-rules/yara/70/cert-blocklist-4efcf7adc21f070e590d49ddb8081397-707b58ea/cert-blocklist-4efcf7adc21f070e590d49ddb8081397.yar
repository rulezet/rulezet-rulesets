import "pe"
rule cert_blocklist_4efcf7adc21f070e590d49ddb8081397 {
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
            pe.signatures[i].subject contains "Ding Ruan" and
            pe.signatures[i].serial == "4e:fc:f7:ad:c2:1f:07:0e:59:0d:49:dd:b8:08:13:97" and
            1476921600 <= pe.signatures[i].not_after
        )
}