import "pe"
rule cert_blocklist_0f203839a9c63b8798a7cb31 {
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
            pe.signatures[i].subject contains "VANKY TECHNOLOGY LIMITED" and
            pe.signatures[i].serial == "0f:20:38:39:a9:c6:3b:87:98:a7:cb:31" and
            1480923809 <= pe.signatures[i].not_after
        )
}