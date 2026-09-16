import "pe"
rule cert_blocklist_5378c5bbeba0d3309a35bb47f63037f7 {
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
            pe.signatures[i].subject contains "OORT inc." and (
                pe.signatures[i].serial == "00:53:78:c5:bb:eb:a0:d3:30:9a:35:bb:47:f6:30:37:f7" or
                pe.signatures[i].serial == "53:78:c5:bb:eb:a0:d3:30:9a:35:bb:47:f6:30:37:f7"
            ) and
            1601427420 <= pe.signatures[i].not_after
        )
}