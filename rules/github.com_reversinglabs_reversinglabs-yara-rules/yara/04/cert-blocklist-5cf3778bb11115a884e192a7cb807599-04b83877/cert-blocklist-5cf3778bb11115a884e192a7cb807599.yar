import "pe"
rule cert_blocklist_5cf3778bb11115a884e192a7cb807599 {
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
            pe.signatures[i].subject contains "SLOMATIC d.o.o." and (
                pe.signatures[i].serial == "00:5c:f3:77:8b:b1:11:15:a8:84:e1:92:a7:cb:80:75:99" or
                pe.signatures[i].serial == "5c:f3:77:8b:b1:11:15:a8:84:e1:92:a7:cb:80:75:99"
            ) and
            1605006199 <= pe.signatures[i].not_after
        )
}