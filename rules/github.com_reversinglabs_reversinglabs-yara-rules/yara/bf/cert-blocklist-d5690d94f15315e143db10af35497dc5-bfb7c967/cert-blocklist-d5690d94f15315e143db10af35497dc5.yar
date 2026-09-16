import "pe"
rule cert_blocklist_d5690d94f15315e143db10af35497dc5 {
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
            pe.signatures[i].subject contains "PET SERVICES d.o.o." and (
                pe.signatures[i].serial == "00:d5:69:0d:94:f1:53:15:e1:43:db:10:af:35:49:7d:c5" or
                pe.signatures[i].serial == "d5:69:0d:94:f1:53:15:e1:43:db:10:af:35:49:7d:c5"
            ) and
            1576195200 <= pe.signatures[i].not_after
        )
}