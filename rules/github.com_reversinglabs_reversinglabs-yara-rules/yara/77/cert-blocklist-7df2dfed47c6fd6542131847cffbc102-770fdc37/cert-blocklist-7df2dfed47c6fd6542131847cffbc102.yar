import "pe"
rule cert_blocklist_7df2dfed47c6fd6542131847cffbc102 {
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
            pe.signatures[i].subject contains "AFVIMPEX SRL" and
            pe.signatures[i].serial == "7d:f2:df:ed:47:c6:fd:65:42:13:18:47:cf:fb:c1:02" and
            1567036800 <= pe.signatures[i].not_after
        )
}