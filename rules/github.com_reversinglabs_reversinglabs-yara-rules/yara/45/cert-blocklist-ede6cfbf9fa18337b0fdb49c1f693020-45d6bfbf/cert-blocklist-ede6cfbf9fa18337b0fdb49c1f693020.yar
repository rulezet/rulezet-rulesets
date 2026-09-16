import "pe"
rule cert_blocklist_ede6cfbf9fa18337b0fdb49c1f693020 {
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
            pe.signatures[i].subject contains "START ARCHITECTURE LTD" and (
                pe.signatures[i].serial == "00:ed:e6:cf:bf:9f:a1:83:37:b0:fd:b4:9c:1f:69:30:20" or
                pe.signatures[i].serial == "ed:e6:cf:bf:9f:a1:83:37:b0:fd:b4:9c:1f:69:30:20"
            ) and
            1554940800 <= pe.signatures[i].not_after
        )
}