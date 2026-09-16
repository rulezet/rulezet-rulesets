import "pe"
rule cert_blocklist_d7c432e8d4edef515bfb9d1c214ff0f5 {
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
            pe.signatures[i].subject contains "LLC \"MILKY PUT\"" and (
                pe.signatures[i].serial == "00:d7:c4:32:e8:d4:ed:ef:51:5b:fb:9d:1c:21:4f:f0:f5" or
                pe.signatures[i].serial == "d7:c4:32:e8:d4:ed:ef:51:5b:fb:9d:1c:21:4f:f0:f5"
            ) and
            1601596800 <= pe.signatures[i].not_after
        )
}