import "pe"
rule cert_blocklist_269174f9fe7c6ed4e1d19b26c3f5b35f {
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
            pe.signatures[i].subject contains "GO ONLINE d.o.o." and
            pe.signatures[i].serial == "26:91:74:f9:fe:7c:6e:d4:e1:d1:9b:26:c3:f5:b3:5f" and
            1586386919 <= pe.signatures[i].not_after
        )
}