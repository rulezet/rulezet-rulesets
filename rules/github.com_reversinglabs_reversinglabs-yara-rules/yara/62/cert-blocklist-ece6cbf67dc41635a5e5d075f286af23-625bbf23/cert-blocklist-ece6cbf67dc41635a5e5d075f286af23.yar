import "pe"
rule cert_blocklist_ece6cbf67dc41635a5e5d075f286af23 {
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
            pe.signatures[i].subject contains "THRANE AGENTUR ApS" and (
                pe.signatures[i].serial == "00:ec:e6:cb:f6:7d:c4:16:35:a5:e5:d0:75:f2:86:af:23" or
                pe.signatures[i].serial == "ec:e6:cb:f6:7d:c4:16:35:a5:e5:d0:75:f2:86:af:23"
            ) and
            1603369254 <= pe.signatures[i].not_after
        )
}