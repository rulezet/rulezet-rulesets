import "pe"
rule cert_blocklist_6b6daef5be29f20ddce4b0f5e9fa6ea5 {
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
            pe.signatures[i].subject contains "Calibration Consultants" and
            pe.signatures[i].serial == "6b:6d:ae:f5:be:29:f2:0d:dc:e4:b0:f5:e9:fa:6e:a5" and
            1280447999 <= pe.signatures[i].not_after
        )
}