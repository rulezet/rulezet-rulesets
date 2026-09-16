import "pe"
rule cert_blocklist_78d1817ebcf338b4e9c810f9740a726b {
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
            pe.signatures[i].subject contains "CONSTRUTORA NOVO PARQUE LTDA - ME" and
            pe.signatures[i].serial == "78:d1:81:7e:bc:f3:38:b4:e9:c8:10:f9:74:0a:72:6b" and
            1431734400 <= pe.signatures[i].not_after
        )
}