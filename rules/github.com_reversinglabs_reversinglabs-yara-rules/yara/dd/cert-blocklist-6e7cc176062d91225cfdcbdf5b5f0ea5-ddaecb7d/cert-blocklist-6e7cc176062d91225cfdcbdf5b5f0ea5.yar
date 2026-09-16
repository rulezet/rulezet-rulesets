import "pe"
rule cert_blocklist_6e7cc176062d91225cfdcbdf5b5f0ea5 {
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
            pe.signatures[i].subject contains "SG Internet" and
            pe.signatures[i].serial == "6e:7c:c1:76:06:2d:91:22:5c:fd:cb:df:5b:5f:0e:a5" and
            1317945600 <= pe.signatures[i].not_after
        )
}