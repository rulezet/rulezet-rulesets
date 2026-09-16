import "pe"
rule cert_blocklist_6eb40ea11eaac847b050de9b59e25bdc {
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
            pe.signatures[i].subject contains "My Free Internet Update" and
            pe.signatures[i].serial == "6e:b4:0e:a1:1e:aa:c8:47:b0:50:de:9b:59:e2:5b:dc" and
            1062201599 <= pe.signatures[i].not_after
        )
}