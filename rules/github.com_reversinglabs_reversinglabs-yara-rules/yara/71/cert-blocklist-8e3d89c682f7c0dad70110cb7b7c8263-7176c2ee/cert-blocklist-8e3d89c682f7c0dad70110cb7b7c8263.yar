import "pe"
rule cert_blocklist_8e3d89c682f7c0dad70110cb7b7c8263 {
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
            pe.signatures[i].subject contains "WORK PLACEMENTS INTERNATIONAL LIMITED" and (
                pe.signatures[i].serial == "00:8e:3d:89:c6:82:f7:c0:da:d7:01:10:cb:7b:7c:82:63" or
                pe.signatures[i].serial == "8e:3d:89:c6:82:f7:c0:da:d7:01:10:cb:7b:7c:82:63"
            ) and
            1570626662 <= pe.signatures[i].not_after
        )
}