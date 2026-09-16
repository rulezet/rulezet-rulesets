import "pe"
rule cert_blocklist_112613b7b5f696cf377680f6463fcc8c {
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
            pe.signatures[i].subject contains "Infoware Cloud Limited" and
            pe.signatures[i].serial == "11:26:13:b7:b5:f6:96:cf:37:76:80:f6:46:3f:cc:8c" and
            1566518400 <= pe.signatures[i].not_after
        )
}