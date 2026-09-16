import "pe"
rule cert_blocklist_0f20a5155e53ce20bb644f646ed6a2fd {
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
            pe.signatures[i].subject contains "CB CAM SP Z O O" and
            pe.signatures[i].serial == "0f:20:a5:15:5e:53:ce:20:bb:64:4f:64:6e:d6:a2:fd" and
            1635196200 <= pe.signatures[i].not_after
        )
}