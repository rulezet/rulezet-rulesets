import "pe"
rule cert_blocklist_61b11ef9726ab2e78132e01bd791b336 {
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
            pe.signatures[i].subject contains "OOO Skalari" and
            pe.signatures[i].serial == "61:b1:1e:f9:72:6a:b2:e7:81:32:e0:1b:d7:91:b3:36" and
            1609372800 <= pe.signatures[i].not_after
        )
}