import "pe"
rule cert_blocklist_88346267057c0a82e2f39851d1b9694c {
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
            pe.signatures[i].subject contains "Hudson LLC" and (
                pe.signatures[i].serial == "00:88:34:62:67:05:7c:0a:82:e2:f3:98:51:d1:b9:69:4c" or
                pe.signatures[i].serial == "88:34:62:67:05:7c:0a:82:e2:f3:98:51:d1:b9:69:4c"
            ) and
            1595376000 <= pe.signatures[i].not_after
        )
}