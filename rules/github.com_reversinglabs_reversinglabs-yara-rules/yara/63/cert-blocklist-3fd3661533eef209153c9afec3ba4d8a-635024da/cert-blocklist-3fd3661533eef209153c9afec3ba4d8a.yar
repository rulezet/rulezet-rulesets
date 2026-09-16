import "pe"
rule cert_blocklist_3fd3661533eef209153c9afec3ba4d8a {
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
            pe.signatures[i].subject contains "SFB Regnskabsservice ApS" and
            pe.signatures[i].serial == "3f:d3:66:15:33:ee:f2:09:15:3c:9a:fe:c3:ba:4d:8a" and
            1614816000 <= pe.signatures[i].not_after
        )
}