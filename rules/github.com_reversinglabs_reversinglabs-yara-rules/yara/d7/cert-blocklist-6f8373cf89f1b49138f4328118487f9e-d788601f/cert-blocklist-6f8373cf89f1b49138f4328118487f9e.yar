import "pe"
rule cert_blocklist_6f8373cf89f1b49138f4328118487f9e {
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
            pe.signatures[i].subject contains "30 PTY LTD" and
            pe.signatures[i].serial == "6f:83:73:cf:89:f1:b4:91:38:f4:32:81:18:48:7f:9e" and
            1572566400 <= pe.signatures[i].not_after
        )
}