import "pe"
rule cert_blocklist_a9c1523cb2c73a82771d318124963e87 {
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
            pe.signatures[i].subject contains "ULTERA" and (
                pe.signatures[i].serial == "00:a9:c1:52:3c:b2:c7:3a:82:77:1d:31:81:24:96:3e:87" or
                pe.signatures[i].serial == "a9:c1:52:3c:b2:c7:3a:82:77:1d:31:81:24:96:3e:87"
            ) and
            1499731200 <= pe.signatures[i].not_after
        )
}