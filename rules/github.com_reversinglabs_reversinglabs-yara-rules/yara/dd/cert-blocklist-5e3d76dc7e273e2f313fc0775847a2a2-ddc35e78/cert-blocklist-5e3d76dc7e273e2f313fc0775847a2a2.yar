import "pe"
rule cert_blocklist_5e3d76dc7e273e2f313fc0775847a2a2 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing Sakula and Derusbi malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "NexG" and
            pe.signatures[i].serial == "5e:3d:76:dc:7e:27:3e:2f:31:3f:c0:77:58:47:a2:a2" and
            1372723199 <= pe.signatures[i].not_after
        )
}