import "pe"
rule cert_blocklist_d08d83ff118df3777e371c5c482cce7b {
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
            pe.signatures[i].subject contains "AMO-K Limited Liability Company" and (
                pe.signatures[i].serial == "00:d0:8d:83:ff:11:8d:f3:77:7e:37:1c:5c:48:2c:ce:7b" or
                pe.signatures[i].serial == "d0:8d:83:ff:11:8d:f3:77:7e:37:1c:5c:48:2c:ce:7b"
            ) and
            1444780800 <= pe.signatures[i].not_after
        )
}