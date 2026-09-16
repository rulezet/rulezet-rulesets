import "pe"
rule cert_blocklist_84a4a0d0657e217b176b455e2465aee0 {
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
            pe.signatures[i].subject contains "AATB ApS" and (
                pe.signatures[i].serial == "00:84:a4:a0:d0:65:7e:21:7b:17:6b:45:5e:24:65:ae:e0" or
                pe.signatures[i].serial == "84:a4:a0:d0:65:7e:21:7b:17:6b:45:5e:24:65:ae:e0"
            ) and
            1616457600 <= pe.signatures[i].not_after
        )
}