import "pe"
rule cert_blocklist_4321de10738278b93683ca542407f103 {
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
            pe.signatures[i].subject contains "We Build Toolbars LLC" and
            pe.signatures[i].serial == "43:21:de:10:73:82:78:b9:36:83:ca:54:24:07:f1:03" and
            1367884800 <= pe.signatures[i].not_after
        )
}