import "pe"
rule cert_blocklist_083e3f {
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
            pe.signatures[i].subject contains "Telefonicasa" and
            pe.signatures[i].serial == "08:3e:3f" and
            999002664 <= pe.signatures[i].not_after
        )
}