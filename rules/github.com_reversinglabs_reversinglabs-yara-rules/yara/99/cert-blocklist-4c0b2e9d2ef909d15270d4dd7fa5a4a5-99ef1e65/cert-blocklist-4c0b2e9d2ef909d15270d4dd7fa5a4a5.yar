import "pe"
rule cert_blocklist_4c0b2e9d2ef909d15270d4dd7fa5a4a5 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing Derusbi malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Fuqing Dawu Technology Co.,Ltd." and
            pe.signatures[i].serial == "4c:0b:2e:9d:2e:f9:09:d1:52:70:d4:dd:7f:a5:a4:a5" and
            1372118399 <= pe.signatures[i].not_after
        )
}