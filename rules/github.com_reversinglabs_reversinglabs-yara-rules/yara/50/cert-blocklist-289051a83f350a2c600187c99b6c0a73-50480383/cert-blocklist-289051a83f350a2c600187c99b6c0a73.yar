import "pe"
rule cert_blocklist_289051a83f350a2c600187c99b6c0a73 {
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
            pe.signatures[i].subject contains "HALL HAULAGE LTD LTD" and
            pe.signatures[i].serial == "28:90:51:a8:3f:35:0a:2c:60:01:87:c9:9b:6c:0a:73" and
            1616716800 <= pe.signatures[i].not_after
        )
}