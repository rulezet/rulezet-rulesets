import "pe"
rule cert_blocklist_984e84cfe362e278f558e2c70aaafac2 {
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
            pe.signatures[i].subject contains "Arctic Nights \\xC3\\x84k\\xC3\\xA4slompolo Oy" and (
                pe.signatures[i].serial == "00:98:4e:84:cf:e3:62:e2:78:f5:58:e2:c7:0a:aa:fa:c2" or
                pe.signatures[i].serial == "98:4e:84:cf:e3:62:e2:78:f5:58:e2:c7:0a:aa:fa:c2"
            ) and
            1640304000 <= pe.signatures[i].not_after
        )
}