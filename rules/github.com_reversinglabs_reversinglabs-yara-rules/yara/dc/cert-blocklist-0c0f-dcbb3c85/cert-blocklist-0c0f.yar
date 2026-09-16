import "pe"
rule cert_blocklist_0c0f {
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
            pe.signatures[i].subject contains "Dmitry Vasilev" and
            pe.signatures[i].serial == "0c:0f" and
            1386719999 <= pe.signatures[i].not_after
        )
}