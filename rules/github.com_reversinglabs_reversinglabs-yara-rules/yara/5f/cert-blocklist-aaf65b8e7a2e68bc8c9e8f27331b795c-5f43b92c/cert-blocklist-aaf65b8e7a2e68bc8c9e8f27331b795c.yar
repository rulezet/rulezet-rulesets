import "pe"
rule cert_blocklist_aaf65b8e7a2e68bc8c9e8f27331b795c {
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
            pe.signatures[i].subject contains "ALISA L LIMITED" and (
                pe.signatures[i].serial == "00:aa:f6:5b:8e:7a:2e:68:bc:8c:9e:8f:27:33:1b:79:5c" or
                pe.signatures[i].serial == "aa:f6:5b:8e:7a:2e:68:bc:8c:9e:8f:27:33:1b:79:5c"
            ) and
            1549324800 <= pe.signatures[i].not_after
        )
}