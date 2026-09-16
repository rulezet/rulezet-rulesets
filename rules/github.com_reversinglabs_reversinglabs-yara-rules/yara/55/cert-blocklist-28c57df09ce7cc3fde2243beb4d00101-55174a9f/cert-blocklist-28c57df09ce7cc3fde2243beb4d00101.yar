import "pe"
rule cert_blocklist_28c57df09ce7cc3fde2243beb4d00101 {
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
            pe.signatures[i].subject contains "WATER, s.r.o." and
            pe.signatures[i].serial == "28:c5:7d:f0:9c:e7:cc:3f:de:22:43:be:b4:d0:01:01" and
            1622678400 <= pe.signatures[i].not_after
        )
}