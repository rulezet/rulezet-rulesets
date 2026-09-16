import "pe"
rule cert_blocklist_e3d5089d4b8f01aadce2731062fb0cce {
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
            pe.signatures[i].subject contains "DEVELOP - Residence s. r. o." and (
                pe.signatures[i].serial == "00:e3:d5:08:9d:4b:8f:01:aa:dc:e2:73:10:62:fb:0c:ce" or
                pe.signatures[i].serial == "e3:d5:08:9d:4b:8f:01:aa:dc:e2:73:10:62:fb:0c:ce"
            ) and
            1618358400 <= pe.signatures[i].not_after
        )
}