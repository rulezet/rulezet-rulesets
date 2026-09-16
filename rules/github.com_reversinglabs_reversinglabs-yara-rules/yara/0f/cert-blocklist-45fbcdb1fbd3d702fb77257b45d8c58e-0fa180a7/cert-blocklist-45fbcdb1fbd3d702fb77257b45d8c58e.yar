import "pe"
rule cert_blocklist_45fbcdb1fbd3d702fb77257b45d8c58e {
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
            pe.signatures[i].subject contains "Ding Ruan" and
            pe.signatures[i].serial == "45:fb:cd:b1:fb:d3:d7:02:fb:77:25:7b:45:d8:c5:8e" and
            1476662400 <= pe.signatures[i].not_after
        )
}