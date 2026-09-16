import "pe"
rule cert_blocklist_3a1b397fd9451e3b5891fc69681ed73d {
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
            pe.signatures[i].subject contains "Yongli Zhang" and
            pe.signatures[i].serial == "3a:1b:39:7f:d9:45:1e:3b:58:91:fc:69:68:1e:d7:3d" and
            1470614400 <= pe.signatures[i].not_after
        )
}