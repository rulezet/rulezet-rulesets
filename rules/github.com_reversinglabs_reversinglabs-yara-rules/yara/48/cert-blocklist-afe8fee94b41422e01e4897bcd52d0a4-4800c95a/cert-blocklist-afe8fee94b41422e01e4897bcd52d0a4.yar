import "pe"
rule cert_blocklist_afe8fee94b41422e01e4897bcd52d0a4 {
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
            pe.signatures[i].subject contains "TLGM ApS" and (
                pe.signatures[i].serial == "00:af:e8:fe:e9:4b:41:42:2e:01:e4:89:7b:cd:52:d0:a4" or
                pe.signatures[i].serial == "af:e8:fe:e9:4b:41:42:2e:01:e4:89:7b:cd:52:d0:a4"
            ) and
            1617062400 <= pe.signatures[i].not_after
        )
}