import "pe"
rule cert_blocklist_b3f906e5e6b2cf61c5e51be79b4e8777 {
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
            pe.signatures[i].subject contains "Accelerate Technologies Ltd" and (
                pe.signatures[i].serial == "00:b3:f9:06:e5:e6:b2:cf:61:c5:e5:1b:e7:9b:4e:87:77" or
                pe.signatures[i].serial == "b3:f9:06:e5:e6:b2:cf:61:c5:e5:1b:e7:9b:4e:87:77"
            ) and
            1594900020 <= pe.signatures[i].not_after
        )
}