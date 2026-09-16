import "pe"
rule cert_blocklist_890570b6b0e2868a53be3f8f904a88ee {
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
            pe.signatures[i].subject contains "JESEN LESS d.o.o." and (
                pe.signatures[i].serial == "00:89:05:70:b6:b0:e2:86:8a:53:be:3f:8f:90:4a:88:ee" or
                pe.signatures[i].serial == "89:05:70:b6:b0:e2:86:8a:53:be:3f:8f:90:4a:88:ee"
            ) and
            1636588800 <= pe.signatures[i].not_after
        )
}