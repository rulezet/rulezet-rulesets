import "pe"
rule cert_blocklist_4a7f07c5d4ad2e23f9e8e03f0e229dd4 {
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
            pe.signatures[i].subject contains "Danalis LLC" and
            pe.signatures[i].serial == "4a:7f:07:c5:d4:ad:2e:23:f9:e8:e0:3f:0e:22:9d:d4" and
            1608681600 <= pe.signatures[i].not_after
        )
}