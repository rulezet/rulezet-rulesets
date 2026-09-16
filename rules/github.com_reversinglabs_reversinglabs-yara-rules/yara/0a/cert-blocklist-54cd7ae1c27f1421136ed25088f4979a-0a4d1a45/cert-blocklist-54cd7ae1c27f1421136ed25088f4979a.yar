import "pe"
rule cert_blocklist_54cd7ae1c27f1421136ed25088f4979a {
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
            pe.signatures[i].subject contains "ABBYMAJUTA LTD LIMITED" and
            pe.signatures[i].serial == "54:cd:7a:e1:c2:7f:14:21:13:6e:d2:50:88:f4:97:9a" and
            1616371200 <= pe.signatures[i].not_after
        )
}