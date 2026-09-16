import "pe"
rule cert_blocklist_0f0ed5318848703405d40f7c62d0f39a {
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
            pe.signatures[i].subject contains "SIES UPRAVLENIE PROTSESSAMI, OOO" and
            pe.signatures[i].serial == "0f:0e:d5:31:88:48:70:34:05:d4:0f:7c:62:d0:f3:9a" and
            1614729600 <= pe.signatures[i].not_after
        )
}