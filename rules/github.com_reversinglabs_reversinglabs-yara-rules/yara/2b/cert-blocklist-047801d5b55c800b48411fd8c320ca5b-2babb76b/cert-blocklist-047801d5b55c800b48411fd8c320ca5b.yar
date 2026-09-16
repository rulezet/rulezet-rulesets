import "pe"
rule cert_blocklist_047801d5b55c800b48411fd8c320ca5b {
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
            pe.signatures[i].subject contains "LICHFIELD STUDIO GLASS LIMITED" and
            pe.signatures[i].serial == "04:78:01:d5:b5:5c:80:0b:48:41:1f:d8:c3:20:ca:5b" and
            1614297600 <= pe.signatures[i].not_after
        )
}