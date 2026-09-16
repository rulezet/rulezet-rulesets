import "pe"
rule cert_blocklist_06a164ec5978497741ee6cec9966871b {
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
            pe.signatures[i].subject contains "JOHN WILLIAM RICHARD" and
            pe.signatures[i].serial == "06:a1:64:ec:59:78:49:77:41:ee:6c:ec:99:66:87:1b" and
            1385596799 <= pe.signatures[i].not_after
        )
}