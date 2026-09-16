import "pe"
rule cert_blocklist_c6ed0efe2844fa44aae350c6845c3331 {
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
            pe.signatures[i].subject contains "THE COMPANY OF WORDS LTD" and (
                pe.signatures[i].serial == "00:c6:ed:0e:fe:28:44:fa:44:aa:e3:50:c6:84:5c:33:31" or
                pe.signatures[i].serial == "c6:ed:0e:fe:28:44:fa:44:aa:e3:50:c6:84:5c:33:31"
            ) and
            1549324800 <= pe.signatures[i].not_after
        )
}