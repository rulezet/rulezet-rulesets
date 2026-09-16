import "pe"
rule cert_blocklist_2e36360538624c9b1afd78a2fb756028 {
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
            pe.signatures[i].subject contains "Ts Trade ApS" and
            pe.signatures[i].serial == "2e:36:36:05:38:62:4c:9b:1a:fd:78:a2:fb:75:60:28" and
            1615766400 <= pe.signatures[i].not_after
        )
}