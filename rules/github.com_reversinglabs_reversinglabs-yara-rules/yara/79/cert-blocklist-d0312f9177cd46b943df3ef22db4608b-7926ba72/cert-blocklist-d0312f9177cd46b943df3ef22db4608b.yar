import "pe"
rule cert_blocklist_d0312f9177cd46b943df3ef22db4608b {
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
            pe.signatures[i].subject contains "United Systems Technology, Inc." and (
                pe.signatures[i].serial == "00:d0:31:2f:91:77:cd:46:b9:43:df:3e:f2:2d:b4:60:8b" or
                pe.signatures[i].serial == "d0:31:2f:91:77:cd:46:b9:43:df:3e:f2:2d:b4:60:8b"
            ) and
            1341273600 <= pe.signatures[i].not_after
        )
}