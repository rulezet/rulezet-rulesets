import "pe"
rule cert_blocklist_c7079866c0e48b01246ba0c148e70d4d {
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
            pe.signatures[i].subject contains "OOO GARANT" and (
                pe.signatures[i].serial == "00:c7:07:98:66:c0:e4:8b:01:24:6b:a0:c1:48:e7:0d:4d" or
                pe.signatures[i].serial == "c7:07:98:66:c0:e4:8b:01:24:6b:a0:c1:48:e7:0d:4d"
            ) and
            1588679105 <= pe.signatures[i].not_after
        )
}