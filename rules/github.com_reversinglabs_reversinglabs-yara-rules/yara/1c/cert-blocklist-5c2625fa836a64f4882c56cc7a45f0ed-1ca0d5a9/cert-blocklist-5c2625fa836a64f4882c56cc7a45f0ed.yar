import "pe"
rule cert_blocklist_5c2625fa836a64f4882c56cc7a45f0ed {
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
            pe.signatures[i].subject contains "Xin Zhou" and
            pe.signatures[i].serial == "5c:26:25:fa:83:6a:64:f4:88:2c:56:cc:7a:45:f0:ed" and
            1474416000 <= pe.signatures[i].not_after
        )
}