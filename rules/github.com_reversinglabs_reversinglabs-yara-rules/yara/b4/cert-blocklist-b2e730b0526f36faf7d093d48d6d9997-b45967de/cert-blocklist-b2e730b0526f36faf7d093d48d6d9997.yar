import "pe"
rule cert_blocklist_b2e730b0526f36faf7d093d48d6d9997 {
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
            pe.signatures[i].subject contains "Bamboo Connect s.r.o." and (
                pe.signatures[i].serial == "00:b2:e7:30:b0:52:6f:36:fa:f7:d0:93:d4:8d:6d:99:97" or
                pe.signatures[i].serial == "b2:e7:30:b0:52:6f:36:fa:f7:d0:93:d4:8d:6d:99:97"
            ) and
            1597276800 <= pe.signatures[i].not_after
        )
}