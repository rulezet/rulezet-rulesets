import "pe"
rule cert_blocklist_2642fe865f7566ce3123a5142c207094 {
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
            pe.signatures[i].subject contains "C.W.D. INSTAL LTD" and
            pe.signatures[i].serial == "26:42:fe:86:5f:75:66:ce:31:23:a5:14:2c:20:70:94" and
            1666310400 <= pe.signatures[i].not_after
        )
}