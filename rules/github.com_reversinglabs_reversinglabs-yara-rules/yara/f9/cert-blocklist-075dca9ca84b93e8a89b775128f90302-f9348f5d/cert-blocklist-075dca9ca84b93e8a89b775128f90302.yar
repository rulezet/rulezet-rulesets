import "pe"
rule cert_blocklist_075dca9ca84b93e8a89b775128f90302 {
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
            pe.signatures[i].subject contains "UAB GT-servis" and
            pe.signatures[i].serial == "07:5d:ca:9c:a8:4b:93:e8:a8:9b:77:51:28:f9:03:02" and
            1579305601 <= pe.signatures[i].not_after
        )
}