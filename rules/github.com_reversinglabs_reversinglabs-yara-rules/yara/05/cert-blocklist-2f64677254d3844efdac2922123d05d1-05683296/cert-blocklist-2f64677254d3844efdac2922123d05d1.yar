import "pe"
rule cert_blocklist_2f64677254d3844efdac2922123d05d1 {
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
            pe.signatures[i].subject contains "ORGANICUP ApS" and
            pe.signatures[i].serial == "2f:64:67:72:54:d3:84:4e:fd:ac:29:22:12:3d:05:d1" and
            1605640092 <= pe.signatures[i].not_after
        )
}