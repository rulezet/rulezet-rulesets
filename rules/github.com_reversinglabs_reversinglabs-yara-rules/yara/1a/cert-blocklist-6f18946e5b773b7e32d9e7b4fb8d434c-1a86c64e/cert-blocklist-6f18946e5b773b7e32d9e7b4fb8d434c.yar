import "pe"
rule cert_blocklist_6f18946e5b773b7e32d9e7b4fb8d434c {
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
            pe.signatures[i].subject contains "VECTOR LLC (VEKTOR, OOO)" and
            pe.signatures[i].serial == "6f:18:94:6e:5b:77:3b:7e:32:d9:e7:b4:fb:8d:43:4c" and
            1454716800 <= pe.signatures[i].not_after
        )
}