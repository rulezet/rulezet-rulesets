import "pe"
rule cert_blocklist_d3aee8abb9948844a3ac1c04cc7e6bdf {
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
            pe.signatures[i].subject contains "HOUSE 9A s.r.o" and (
                pe.signatures[i].serial == "00:d3:ae:e8:ab:b9:94:88:44:a3:ac:1c:04:cc:7e:6b:df" or
                pe.signatures[i].serial == "d3:ae:e8:ab:b9:94:88:44:a3:ac:1c:04:cc:7e:6b:df"
            ) and
            1640822400 <= pe.signatures[i].not_after
        )
}