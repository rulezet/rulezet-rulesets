import "pe"
rule cert_blocklist_0e8aa328af207ce8bcae1dc15c626188 {
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
            pe.signatures[i].subject contains "PRO SAT SRL" and
            pe.signatures[i].serial == "0e:8a:a3:28:af:20:7c:e8:bc:ae:1d:c1:5c:62:61:88" and
            1627344000 <= pe.signatures[i].not_after
        )
}