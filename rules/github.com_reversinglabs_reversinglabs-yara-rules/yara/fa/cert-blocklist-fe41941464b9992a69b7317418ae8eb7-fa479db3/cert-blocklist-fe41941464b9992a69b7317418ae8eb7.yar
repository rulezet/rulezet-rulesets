import "pe"
rule cert_blocklist_fe41941464b9992a69b7317418ae8eb7 {
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
            pe.signatures[i].subject contains "Milsean Software Limited" and (
                pe.signatures[i].serial == "00:fe:41:94:14:64:b9:99:2a:69:b7:31:74:18:ae:8e:b7" or
                pe.signatures[i].serial == "fe:41:94:14:64:b9:99:2a:69:b7:31:74:18:ae:8e:b7"
            ) and
            1599523200 <= pe.signatures[i].not_after
        )
}