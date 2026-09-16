import "pe"
rule cert_blocklist_1ffc9825644caf5b1f521780c5c7f42c {
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
            pe.signatures[i].subject contains "ACTIVUS LIMITED" and
            pe.signatures[i].serial == "1f:fc:98:25:64:4c:af:5b:1f:52:17:80:c5:c7:f4:2c" and
            1615507200 <= pe.signatures[i].not_after
        )
}