import "pe"
rule cert_blocklist_48cad4e6966e22d6 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing OSX DokSpy backdoor."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Developer ID Application: Seven Muller (FUP9692NN6)" and
            pe.signatures[i].serial == "48:ca:d4:e6:96:6e:22:d6" and
            1492732799 <= pe.signatures[i].not_after
        )
}