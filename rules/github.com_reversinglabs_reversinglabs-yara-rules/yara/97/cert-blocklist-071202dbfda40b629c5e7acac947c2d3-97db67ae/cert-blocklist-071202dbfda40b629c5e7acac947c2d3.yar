import "pe"
rule cert_blocklist_071202dbfda40b629c5e7acac947c2d3 {
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
            pe.signatures[i].subject contains "Crossfire Industries, LLC" and
            pe.signatures[i].serial == "07:12:02:db:fd:a4:0b:62:9c:5e:7a:ca:c9:47:c2:d3" and
            1658620801 <= pe.signatures[i].not_after
        )
}