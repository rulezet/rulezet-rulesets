import "pe"
rule cert_blocklist_0a2787fbb4627c91611573e323584113 {
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
            pe.signatures[i].subject contains "exxon.com" and
            pe.signatures[i].serial == "0a:27:87:fb:b4:62:7c:91:61:15:73:e3:23:58:41:13" and
            1640822400 <= pe.signatures[i].not_after
        )
}