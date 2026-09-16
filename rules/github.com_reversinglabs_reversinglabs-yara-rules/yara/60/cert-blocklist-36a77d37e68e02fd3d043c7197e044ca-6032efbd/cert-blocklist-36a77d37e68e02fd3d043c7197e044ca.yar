import "pe"
rule cert_blocklist_36a77d37e68e02fd3d043c7197e044ca {
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
            pe.signatures[i].subject contains "Direct Systems Ltd" and
            pe.signatures[i].serial == "36:a7:7d:37:e6:8e:02:fd:3d:04:3c:71:97:e0:44:ca" and
            1515542400 <= pe.signatures[i].not_after
        )
}