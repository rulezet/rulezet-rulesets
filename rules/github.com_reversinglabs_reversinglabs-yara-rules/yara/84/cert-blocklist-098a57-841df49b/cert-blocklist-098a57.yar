import "pe"
rule cert_blocklist_098a57 {
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
            pe.signatures[i].subject contains "ELECTRONIC GROUP" and
            pe.signatures[i].serial == "09:8a:57" and
            1032855179 <= pe.signatures[i].not_after
        )
}