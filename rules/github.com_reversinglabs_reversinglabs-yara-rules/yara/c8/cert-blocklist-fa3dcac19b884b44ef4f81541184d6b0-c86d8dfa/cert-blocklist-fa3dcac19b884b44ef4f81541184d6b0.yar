import "pe"
rule cert_blocklist_fa3dcac19b884b44ef4f81541184d6b0 {
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
            pe.signatures[i].subject contains "Unicom Ltd" and (
                pe.signatures[i].serial == "00:fa:3d:ca:c1:9b:88:4b:44:ef:4f:81:54:11:84:d6:b0" or
                pe.signatures[i].serial == "fa:3d:ca:c1:9b:88:4b:44:ef:4f:81:54:11:84:d6:b0"
            ) and
            1603958571 <= pe.signatures[i].not_after
        )
}