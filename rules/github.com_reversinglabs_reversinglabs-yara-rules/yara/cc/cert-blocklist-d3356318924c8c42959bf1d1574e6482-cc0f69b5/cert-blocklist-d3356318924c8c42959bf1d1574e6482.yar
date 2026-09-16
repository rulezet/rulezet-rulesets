import "pe"
rule cert_blocklist_d3356318924c8c42959bf1d1574e6482 {
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
            pe.signatures[i].subject contains "ADV TOURS d.o.o." and (
                pe.signatures[i].serial == "00:d3:35:63:18:92:4c:8c:42:95:9b:f1:d1:57:4e:64:82" or
                pe.signatures[i].serial == "d3:35:63:18:92:4c:8c:42:95:9b:f1:d1:57:4e:64:82"
            ) and
            1613001600 <= pe.signatures[i].not_after
        )
}