import "pe"
rule cert_blocklist_32bc299f0694c19ec21e71265b1d7e17 {
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
            pe.signatures[i].subject contains "Yu Bao" and
            pe.signatures[i].serial == "32:bc:29:9f:06:94:c1:9e:c2:1e:71:26:5b:1d:7e:17" and
            1474416000 <= pe.signatures[i].not_after
        )
}