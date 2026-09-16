import "pe"
rule cert_blocklist_6171990ba1c8e71049ebb296a35bd160 {
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
            pe.signatures[i].subject contains "OWLNET LIMITED" and
            pe.signatures[i].serial == "61:71:99:0b:a1:c8:e7:10:49:eb:b2:96:a3:5b:d1:60" and
            1620000000 <= pe.signatures[i].not_after
        )
}