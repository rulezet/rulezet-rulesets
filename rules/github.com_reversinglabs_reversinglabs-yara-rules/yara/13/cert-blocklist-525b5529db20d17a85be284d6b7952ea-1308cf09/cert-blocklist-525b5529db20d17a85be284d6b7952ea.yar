import "pe"
rule cert_blocklist_525b5529db20d17a85be284d6b7952ea {
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
            pe.signatures[i].serial == "52:5b:55:29:db:20:d1:7a:85:be:28:4d:6b:79:52:ea" and
            1508198400 <= pe.signatures[i].not_after
        )
}