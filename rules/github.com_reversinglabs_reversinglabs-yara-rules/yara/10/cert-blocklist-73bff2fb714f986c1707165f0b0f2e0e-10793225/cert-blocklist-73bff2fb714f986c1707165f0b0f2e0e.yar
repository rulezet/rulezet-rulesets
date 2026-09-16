import "pe"
rule cert_blocklist_73bff2fb714f986c1707165f0b0f2e0e {
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
            pe.signatures[i].subject contains "Tecnopolis Consulting Ltd" and
            pe.signatures[i].serial == "73:bf:f2:fb:71:4f:98:6c:17:07:16:5f:0b:0f:2e:0e" and
            1090886400 <= pe.signatures[i].not_after
        )
}