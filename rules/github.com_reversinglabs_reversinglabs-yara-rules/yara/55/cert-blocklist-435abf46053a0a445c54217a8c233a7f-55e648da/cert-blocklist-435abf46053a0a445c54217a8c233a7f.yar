import "pe"
rule cert_blocklist_435abf46053a0a445c54217a8c233a7f {
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
            pe.signatures[i].subject contains "OOO Kodemika" and
            pe.signatures[i].serial == "43:5a:bf:46:05:3a:0a:44:5c:54:21:7a:8c:23:3a:7f" and
            1616976000 <= pe.signatures[i].not_after
        )
}