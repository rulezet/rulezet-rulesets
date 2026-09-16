import "pe"
rule cert_blocklist_6dc86ebf5863568e2237b2d89582d705 {
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
            pe.signatures[i].subject contains "Dening Hu" and
            pe.signatures[i].serial == "6d:c8:6e:bf:58:63:56:8e:22:37:b2:d8:95:82:d7:05" and
            1471305600 <= pe.signatures[i].not_after
        )
}