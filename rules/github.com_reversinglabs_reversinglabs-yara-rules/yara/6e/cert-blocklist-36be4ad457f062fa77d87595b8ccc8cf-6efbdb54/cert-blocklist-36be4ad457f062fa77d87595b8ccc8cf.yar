import "pe"
rule cert_blocklist_36be4ad457f062fa77d87595b8ccc8cf {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing Careto malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "TecSystem Ltd." and
            pe.signatures[i].serial == "36:be:4a:d4:57:f0:62:fa:77:d8:75:95:b8:cc:c8:cf" and
            1372377599 <= pe.signatures[i].not_after
        )
}