import "pe"
rule cert_blocklist_239664c12baeb5a6d787912888051392 {
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
            pe.signatures[i].subject contains "FORTH PROPERTY LTD" and
            pe.signatures[i].serial == "23:96:64:c1:2b:ae:b5:a6:d7:87:91:28:88:05:13:92" and
            1618272000 <= pe.signatures[i].not_after
        )
}