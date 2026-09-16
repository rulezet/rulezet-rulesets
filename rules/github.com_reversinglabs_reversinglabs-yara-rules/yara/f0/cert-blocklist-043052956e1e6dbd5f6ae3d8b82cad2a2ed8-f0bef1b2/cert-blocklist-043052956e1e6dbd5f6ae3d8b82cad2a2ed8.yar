import "pe"
rule cert_blocklist_043052956e1e6dbd5f6ae3d8b82cad2a2ed8 {
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
            pe.signatures[i].subject contains "ok.com" and
            pe.signatures[i].serial == "04:30:52:95:6e:1e:6d:bd:5f:6a:e3:d8:b8:2c:ad:2a:2e:d8" and
            1662149613 <= pe.signatures[i].not_after
        )
}