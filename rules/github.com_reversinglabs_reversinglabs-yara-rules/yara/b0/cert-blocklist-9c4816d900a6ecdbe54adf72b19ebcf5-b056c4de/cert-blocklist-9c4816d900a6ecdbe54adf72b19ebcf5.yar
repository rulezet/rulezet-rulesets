import "pe"
rule cert_blocklist_9c4816d900a6ecdbe54adf72b19ebcf5 {
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
            pe.signatures[i].subject contains "Datamingo Limited" and (
                pe.signatures[i].serial == "00:9c:48:16:d9:00:a6:ec:db:e5:4a:df:72:b1:9e:bc:f5" or
                pe.signatures[i].serial == "9c:48:16:d9:00:a6:ec:db:e5:4a:df:72:b1:9e:bc:f5"
            ) and
            1557187200 <= pe.signatures[i].not_after
        )
}