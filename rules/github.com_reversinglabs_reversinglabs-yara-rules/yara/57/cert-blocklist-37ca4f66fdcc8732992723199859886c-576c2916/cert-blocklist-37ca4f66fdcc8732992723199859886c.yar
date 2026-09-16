import "pe"
rule cert_blocklist_37ca4f66fdcc8732992723199859886c {
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
            pe.signatures[i].subject contains "Aleman Ltd" and
            pe.signatures[i].serial == "37:ca:4f:66:fd:cc:87:32:99:27:23:19:98:59:88:6c" and
            1505952000 <= pe.signatures[i].not_after
        )
}