import "pe"
rule cert_blocklist_065569a3e261409128a40affa90d6d10 {
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
            pe.signatures[i].subject contains "Police Mutual Aid Association" and
            pe.signatures[i].serial == "06:55:69:a3:e2:61:40:91:28:a4:0a:ff:a9:0d:6d:10" and
            1381795199 <= pe.signatures[i].not_after
        )
}