import "pe"
rule cert_blocklist_31062e483e0106b18c982f0053185c36 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing Sakula malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "MICRO DIGITAL INC." and
            pe.signatures[i].serial == "31:06:2e:48:3e:01:06:b1:8c:98:2f:00:53:18:5c:36" and
            1332287999 <= pe.signatures[i].not_after
        )
}