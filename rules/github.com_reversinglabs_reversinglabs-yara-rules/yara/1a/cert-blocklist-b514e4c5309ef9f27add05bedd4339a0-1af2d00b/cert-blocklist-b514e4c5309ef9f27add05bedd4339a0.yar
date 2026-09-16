import "pe"
rule cert_blocklist_b514e4c5309ef9f27add05bedd4339a0 {
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
            pe.signatures[i].subject contains "SCABONE PTY LTD" and (
                pe.signatures[i].serial == "00:b5:14:e4:c5:30:9e:f9:f2:7a:dd:05:be:dd:43:39:a0" or
                pe.signatures[i].serial == "b5:14:e4:c5:30:9e:f9:f2:7a:dd:05:be:dd:43:39:a0"
            ) and
            1572566400 <= pe.signatures[i].not_after
        )
}