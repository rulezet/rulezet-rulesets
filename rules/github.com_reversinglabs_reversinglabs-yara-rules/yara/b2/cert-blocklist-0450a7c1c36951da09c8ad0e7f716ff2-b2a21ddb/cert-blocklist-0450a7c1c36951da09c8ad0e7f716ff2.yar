import "pe"
rule cert_blocklist_0450a7c1c36951da09c8ad0e7f716ff2 {
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
            pe.signatures[i].subject contains "PS Partnership" and
            pe.signatures[i].serial == "04:50:a7:c1:c3:69:51:da:09:c8:ad:0e:7f:71:6f:f2" and
            1362182399 <= pe.signatures[i].not_after
        )
}