import "pe"
rule cert_blocklist_7d36cbb64bc9add17ba71737d3ecceca {
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
            pe.signatures[i].subject contains "LTD SERVICES LIMITED" and
            pe.signatures[i].serial == "7d:36:cb:b6:4b:c9:ad:d1:7b:a7:17:37:d3:ec:ce:ca" and
            1616025600 <= pe.signatures[i].not_after
        )
}