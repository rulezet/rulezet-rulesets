import "pe"
rule cert_blocklist_37d36a4e61c0ac68ceb8bfcef2dbf283 {
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
            pe.signatures[i].subject contains "ANAVERIS LIMITED" and
            pe.signatures[i].serial == "37:d3:6a:4e:61:c0:ac:68:ce:b8:bf:ce:f2:db:f2:83" and
            1532476800 <= pe.signatures[i].not_after
        )
}