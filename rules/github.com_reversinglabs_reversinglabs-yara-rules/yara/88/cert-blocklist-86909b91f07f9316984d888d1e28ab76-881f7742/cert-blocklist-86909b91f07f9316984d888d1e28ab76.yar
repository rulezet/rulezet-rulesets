import "pe"
rule cert_blocklist_86909b91f07f9316984d888d1e28ab76 {
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
            pe.signatures[i].subject contains "Dantherm Intelligent Monitoring A/S" and (
                pe.signatures[i].serial == "00:86:90:9b:91:f0:7f:93:16:98:4d:88:8d:1e:28:ab:76" or
                pe.signatures[i].serial == "86:90:9b:91:f0:7f:93:16:98:4d:88:8d:1e:28:ab:76"
            ) and
            1611273600 <= pe.signatures[i].not_after
        )
}