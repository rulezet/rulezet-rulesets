import "pe"
rule cert_blocklist_3ad60cea73e1dd1a3e6c02d9b339c380 {
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
            pe.signatures[i].subject contains "CUS Software GmbH" and
            pe.signatures[i].serial == "3a:d6:0c:ea:73:e1:dd:1a:3e:6c:02:d9:b3:39:c3:80" and
            1567036800 <= pe.signatures[i].not_after
        )
}