import "pe"
rule cert_blocklist_92d9b92f8cf7a1ba8b2c025be730c300 {
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
            pe.signatures[i].subject contains "UPLagga Systems s.r.o." and (
                pe.signatures[i].serial == "00:92:d9:b9:2f:8c:f7:a1:ba:8b:2c:02:5b:e7:30:c3:00" or
                pe.signatures[i].serial == "92:d9:b9:2f:8c:f7:a1:ba:8b:2c:02:5b:e7:30:c3:00"
            ) and
            1598054400 <= pe.signatures[i].not_after
        )
}