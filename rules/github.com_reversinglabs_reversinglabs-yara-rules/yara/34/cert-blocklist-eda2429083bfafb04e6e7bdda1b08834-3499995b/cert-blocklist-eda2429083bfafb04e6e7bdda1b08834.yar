import "pe"
rule cert_blocklist_eda2429083bfafb04e6e7bdda1b08834 {
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
            pe.signatures[i].subject contains "OWLNET LIMITED" and (
                pe.signatures[i].serial == "00:ed:a2:42:90:83:bf:af:b0:4e:6e:7b:dd:a1:b0:88:34" or
                pe.signatures[i].serial == "ed:a2:42:90:83:bf:af:b0:4e:6e:7b:dd:a1:b0:88:34"
            ) and
            1625011200 <= pe.signatures[i].not_after
        )
}