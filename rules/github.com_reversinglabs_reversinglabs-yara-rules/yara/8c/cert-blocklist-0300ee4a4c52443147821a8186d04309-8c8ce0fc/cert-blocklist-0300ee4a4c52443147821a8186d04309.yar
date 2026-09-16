import "pe"
rule cert_blocklist_0300ee4a4c52443147821a8186d04309 {
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
            pe.signatures[i].subject contains "Buster Ind Com Imp e Exp de Acessorios P Autos Ltda" and
            pe.signatures[i].serial == "03:00:ee:4a:4c:52:44:31:47:82:1a:81:86:d0:43:09" and
            1494892800 <= pe.signatures[i].not_after
        )
}