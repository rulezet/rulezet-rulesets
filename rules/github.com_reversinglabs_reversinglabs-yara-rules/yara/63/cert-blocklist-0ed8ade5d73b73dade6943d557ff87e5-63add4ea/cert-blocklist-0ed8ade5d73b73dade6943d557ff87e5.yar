import "pe"
rule cert_blocklist_0ed8ade5d73b73dade6943d557ff87e5 {
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
            pe.signatures[i].subject contains "Rumikon LLC" and
            pe.signatures[i].serial == "0e:d8:ad:e5:d7:3b:73:da:de:69:43:d5:57:ff:87:e5" and
            1597885200 <= pe.signatures[i].not_after
        )
}