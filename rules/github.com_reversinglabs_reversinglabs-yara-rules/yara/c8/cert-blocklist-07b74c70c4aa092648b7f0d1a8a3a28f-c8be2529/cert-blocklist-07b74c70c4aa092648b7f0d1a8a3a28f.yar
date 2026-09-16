import "pe"
rule cert_blocklist_07b74c70c4aa092648b7f0d1a8a3a28f {
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
            pe.signatures[i].subject contains "Rad-Grad D.O.O." and
            pe.signatures[i].serial == "07:b7:4c:70:c4:aa:09:26:48:b7:f0:d1:a8:a3:a2:8f" and
            1603240965 <= pe.signatures[i].not_after
        )
}