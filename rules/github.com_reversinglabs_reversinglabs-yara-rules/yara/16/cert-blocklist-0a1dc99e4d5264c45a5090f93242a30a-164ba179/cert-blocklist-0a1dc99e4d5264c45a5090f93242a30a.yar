import "pe"
rule cert_blocklist_0a1dc99e4d5264c45a5090f93242a30a {
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
            pe.signatures[i].subject contains "K & D KOMPANI d.o.o." and
            pe.signatures[i].serial == "0a:1d:c9:9e:4d:52:64:c4:5a:50:90:f9:32:42:a3:0a" and
            1600905601 <= pe.signatures[i].not_after
        )
}