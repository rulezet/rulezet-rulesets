import "pe"
rule cert_blocklist_b06bc166fc765dacd2f7448c8cdd9205 {
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
            pe.signatures[i].subject contains "GAS Avto, d.o.o." and (
                pe.signatures[i].serial == "00:b0:6b:c1:66:fc:76:5d:ac:d2:f7:44:8c:8c:dd:92:05" or
                pe.signatures[i].serial == "b0:6b:c1:66:fc:76:5d:ac:d2:f7:44:8c:8c:dd:92:05"
            ) and
            1615507200 <= pe.signatures[i].not_after
        )
}