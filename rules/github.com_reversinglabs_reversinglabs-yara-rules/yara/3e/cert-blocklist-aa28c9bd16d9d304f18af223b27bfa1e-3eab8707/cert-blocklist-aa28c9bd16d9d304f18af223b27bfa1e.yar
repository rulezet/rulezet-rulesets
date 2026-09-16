import "pe"
rule cert_blocklist_aa28c9bd16d9d304f18af223b27bfa1e {
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
            pe.signatures[i].subject contains "Tecno trade d.o.o." and (
                pe.signatures[i].serial == "00:aa:28:c9:bd:16:d9:d3:04:f1:8a:f2:23:b2:7b:fa:1e" or
                pe.signatures[i].serial == "aa:28:c9:bd:16:d9:d3:04:f1:8a:f2:23:b2:7b:fa:1e"
            ) and
            1611705600 <= pe.signatures[i].not_after
        )
}