import "pe"
rule cert_blocklist_cbf91988fb83511de1b3a7a520712e9c {
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
            pe.signatures[i].subject contains "Ltd. \"Eve Beauty\"" and (
                pe.signatures[i].serial == "00:cb:f9:19:88:fb:83:51:1d:e1:b3:a7:a5:20:71:2e:9c" or
                pe.signatures[i].serial == "cb:f9:19:88:fb:83:51:1d:e1:b3:a7:a5:20:71:2e:9c"
            ) and
            1578786662 <= pe.signatures[i].not_after
        )
}