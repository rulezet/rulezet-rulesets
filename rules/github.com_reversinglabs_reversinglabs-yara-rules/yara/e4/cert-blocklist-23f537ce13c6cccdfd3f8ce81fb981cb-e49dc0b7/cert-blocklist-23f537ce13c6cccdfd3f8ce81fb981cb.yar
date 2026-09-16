import "pe"
rule cert_blocklist_23f537ce13c6cccdfd3f8ce81fb981cb {
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
            pe.signatures[i].subject contains "ISECURE GROUP PTY LTD" and
            pe.signatures[i].serial == "23:f5:37:ce:13:c6:cc:cd:fd:3f:8c:e8:1f:b9:81:cb" and
            1566086400 <= pe.signatures[i].not_after
        )
}