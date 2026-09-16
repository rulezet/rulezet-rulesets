import "pe"
rule cert_blocklist_0d83e7f47189cdbfc7fa3e5f58882329 {
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
            pe.signatures[i].subject contains "THE WIZARD GIFT CORPORATION" and
            pe.signatures[i].serial == "0d:83:e7:f4:71:89:cd:bf:c7:fa:3e:5f:58:88:23:29" and
            1605830400 <= pe.signatures[i].not_after
        )
}