import "pe"
rule cert_blocklist_bc6a1812e001362469541108973bbd52 {
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
            pe.signatures[i].subject contains "AMCERT,LLC" and (
                pe.signatures[i].serial == "00:bc:6a:18:12:e0:01:36:24:69:54:11:08:97:3b:bd:52" or
                pe.signatures[i].serial == "bc:6a:18:12:e0:01:36:24:69:54:11:08:97:3b:bd:52"
            ) and
            1623801600 <= pe.signatures[i].not_after
        )
}