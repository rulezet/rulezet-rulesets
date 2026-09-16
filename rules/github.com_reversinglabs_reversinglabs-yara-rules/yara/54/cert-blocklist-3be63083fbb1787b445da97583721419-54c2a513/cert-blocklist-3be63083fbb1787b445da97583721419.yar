import "pe"
rule cert_blocklist_3be63083fbb1787b445da97583721419 {
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
            pe.signatures[i].subject contains "\"SMART GREY\" LLC" and
            pe.signatures[i].serial == "3b:e6:30:83:fb:b1:78:7b:44:5d:a9:75:83:72:14:19" and
            1493942400 <= pe.signatures[i].not_after
        )
}