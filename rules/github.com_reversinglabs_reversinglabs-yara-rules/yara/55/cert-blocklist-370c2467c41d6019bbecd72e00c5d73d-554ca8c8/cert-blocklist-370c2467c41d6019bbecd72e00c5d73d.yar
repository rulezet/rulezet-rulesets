import "pe"
rule cert_blocklist_370c2467c41d6019bbecd72e00c5d73d {
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
            pe.signatures[i].subject contains "UNINFO SISTEMAS LTDA ME" and
            pe.signatures[i].serial == "37:0c:24:67:c4:1d:60:19:bb:ec:d7:2e:00:c5:d7:3d" and
            1445299199 <= pe.signatures[i].not_after
        )
}