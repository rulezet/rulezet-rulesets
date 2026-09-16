import "pe"
rule cert_blocklist_0883db137021b51f3a2a08a76a4bc066 {
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
            pe.signatures[i].subject contains "Divertida Creative Limited" and
            pe.signatures[i].serial == "08:83:db:13:70:21:b5:1f:3a:2a:08:a7:6a:4b:c0:66" and
            1627430400 <= pe.signatures[i].not_after
        )
}