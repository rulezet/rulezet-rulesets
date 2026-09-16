import "pe"
rule cert_blocklist_a46f9d8784778baa48167c48bbc56f30 {
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
            pe.signatures[i].subject contains "Mapping OOO" and (
                pe.signatures[i].serial == "00:a4:6f:9d:87:84:77:8b:aa:48:16:7c:48:bb:c5:6f:30" or
                pe.signatures[i].serial == "a4:6f:9d:87:84:77:8b:aa:48:16:7c:48:bb:c5:6f:30"
            ) and
            1618963200 <= pe.signatures[i].not_after
        )
}