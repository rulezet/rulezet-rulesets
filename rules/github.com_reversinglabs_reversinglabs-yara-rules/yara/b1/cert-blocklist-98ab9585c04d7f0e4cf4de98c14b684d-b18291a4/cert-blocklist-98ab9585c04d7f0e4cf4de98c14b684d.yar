import "pe"
rule cert_blocklist_98ab9585c04d7f0e4cf4de98c14b684d {
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
            pe.signatures[i].subject contains "AMCERT,LLC" and (
                pe.signatures[i].serial == "00:98:ab:95:85:c0:4d:7f:0e:4c:f4:de:98:c1:4b:68:4d" or
                pe.signatures[i].serial == "98:ab:95:85:c0:4d:7f:0e:4c:f4:de:98:c1:4b:68:4d"
            ) and
            1656547200 <= pe.signatures[i].not_after
        )
}