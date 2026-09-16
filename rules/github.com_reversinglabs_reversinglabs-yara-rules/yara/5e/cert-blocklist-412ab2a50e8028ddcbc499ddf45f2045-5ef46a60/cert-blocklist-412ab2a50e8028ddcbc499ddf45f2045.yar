import "pe"
rule cert_blocklist_412ab2a50e8028ddcbc499ddf45f2045 {
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
            pe.signatures[i].subject contains "Ding Ruan" and
            pe.signatures[i].serial == "41:2a:b2:a5:0e:80:28:dd:cb:c4:99:dd:f4:5f:20:45" and
            1479340800 <= pe.signatures[i].not_after
        )
}