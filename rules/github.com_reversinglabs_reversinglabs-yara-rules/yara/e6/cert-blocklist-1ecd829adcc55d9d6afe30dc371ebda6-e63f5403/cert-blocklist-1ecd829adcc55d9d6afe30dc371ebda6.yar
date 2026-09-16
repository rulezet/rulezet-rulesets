import "pe"
rule cert_blocklist_1ecd829adcc55d9d6afe30dc371ebda6 {
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
            pe.signatures[i].subject contains "OOO Komp.IT" and (
                pe.signatures[i].serial == "00:1e:cd:82:9a:dc:c5:5d:9d:6a:fe:30:dc:37:1e:bd:a6" or
                pe.signatures[i].serial == "1e:cd:82:9a:dc:c5:5d:9d:6a:fe:30:dc:37:1e:bd:a6"
            ) and
            1588723200 <= pe.signatures[i].not_after
        )
}