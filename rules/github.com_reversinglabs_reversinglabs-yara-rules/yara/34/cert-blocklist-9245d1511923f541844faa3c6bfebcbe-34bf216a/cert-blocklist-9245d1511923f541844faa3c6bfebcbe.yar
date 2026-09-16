import "pe"
rule cert_blocklist_9245d1511923f541844faa3c6bfebcbe {
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
            pe.signatures[i].subject contains "LEHTEH d.o.o., Ljubljana" and (
                pe.signatures[i].serial == "00:92:45:d1:51:19:23:f5:41:84:4f:aa:3c:6b:fe:bc:be" or
                pe.signatures[i].serial == "92:45:d1:51:19:23:f5:41:84:4f:aa:3c:6b:fe:bc:be"
            ) and
            1607040000 <= pe.signatures[i].not_after
        )
}