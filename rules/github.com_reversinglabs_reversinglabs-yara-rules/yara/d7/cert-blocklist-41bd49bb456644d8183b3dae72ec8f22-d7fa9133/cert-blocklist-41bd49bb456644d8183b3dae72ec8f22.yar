import "pe"
rule cert_blocklist_41bd49bb456644d8183b3dae72ec8f22 {
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
            pe.signatures[i].subject contains "Xin Zhou" and
            pe.signatures[i].serial == "41:bd:49:bb:45:66:44:d8:18:3b:3d:ae:72:ec:8f:22" and
            1468454400 <= pe.signatures[i].not_after
        )
}