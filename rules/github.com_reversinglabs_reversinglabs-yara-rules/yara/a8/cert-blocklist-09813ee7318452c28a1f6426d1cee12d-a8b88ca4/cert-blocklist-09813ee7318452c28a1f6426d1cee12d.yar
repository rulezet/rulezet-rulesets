import "pe"
rule cert_blocklist_09813ee7318452c28a1f6426d1cee12d {
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
            pe.signatures[i].subject contains "Saly Younes" and
            pe.signatures[i].serial == "09:81:3e:e7:31:84:52:c2:8a:1f:64:26:d1:ce:e1:2d" and
            1455667199 <= pe.signatures[i].not_after
        )
}