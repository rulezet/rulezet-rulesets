import "pe"
rule cert_blocklist_7289b0f9bd641e3e352dc3183f8de6be {
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
            pe.signatures[i].subject contains "ICE ACTIVATION LIMITED" and
            pe.signatures[i].serial == "72:89:b0:f9:bd:64:1e:3e:35:2d:c3:18:3f:8d:e6:be" and
            1557933274 <= pe.signatures[i].not_after
        )
}