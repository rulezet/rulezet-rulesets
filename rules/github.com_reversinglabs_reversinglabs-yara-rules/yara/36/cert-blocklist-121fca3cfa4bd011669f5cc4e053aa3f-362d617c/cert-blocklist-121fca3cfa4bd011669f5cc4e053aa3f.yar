import "pe"
rule cert_blocklist_121fca3cfa4bd011669f5cc4e053aa3f {
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
            pe.signatures[i].subject contains "Kymijoen Projektipalvelut Oy" and
            pe.signatures[i].serial == "12:1f:ca:3c:fa:4b:d0:11:66:9f:5c:c4:e0:53:aa:3f" and
            1606953600 <= pe.signatures[i].not_after
        )
}