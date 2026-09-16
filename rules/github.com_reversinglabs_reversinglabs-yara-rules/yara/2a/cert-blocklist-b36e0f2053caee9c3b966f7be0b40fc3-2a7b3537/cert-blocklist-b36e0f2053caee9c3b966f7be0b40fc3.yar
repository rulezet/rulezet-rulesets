import "pe"
rule cert_blocklist_b36e0f2053caee9c3b966f7be0b40fc3 {
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
            pe.signatures[i].subject contains "PARTS-JEST d.o.o." and (
                pe.signatures[i].serial == "00:b3:6e:0f:20:53:ca:ee:9c:3b:96:6f:7b:e0:b4:0f:c3" or
                pe.signatures[i].serial == "b3:6e:0f:20:53:ca:ee:9c:3b:96:6f:7b:e0:b4:0f:c3"
            ) and
            1600172855 <= pe.signatures[i].not_after
        )
}