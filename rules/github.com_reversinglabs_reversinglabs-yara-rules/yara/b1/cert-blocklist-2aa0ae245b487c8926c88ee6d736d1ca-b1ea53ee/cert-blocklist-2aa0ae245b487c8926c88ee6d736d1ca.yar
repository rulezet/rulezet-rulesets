import "pe"
rule cert_blocklist_2aa0ae245b487c8926c88ee6d736d1ca {
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
            pe.signatures[i].subject contains "PILOTE SPRL" and
            pe.signatures[i].serial == "2a:a0:ae:24:5b:48:7c:89:26:c8:8e:e6:d7:36:d1:ca" and
            1612262280 <= pe.signatures[i].not_after
        )
}