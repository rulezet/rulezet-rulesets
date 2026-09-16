import "pe"
rule cert_blocklist_e86f46b60142092aae81b8f6fa3d9c7c {
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
            pe.signatures[i].subject contains "Syncode Sistemas e Tecnologia Ltda" and (
                pe.signatures[i].serial == "00:e8:6f:46:b6:01:42:09:2a:ae:81:b8:f6:fa:3d:9c:7c" or
                pe.signatures[i].serial == "e8:6f:46:b6:01:42:09:2a:ae:81:b8:f6:fa:3d:9c:7c"
            ) and
            1373932799 <= pe.signatures[i].not_after
        )
}