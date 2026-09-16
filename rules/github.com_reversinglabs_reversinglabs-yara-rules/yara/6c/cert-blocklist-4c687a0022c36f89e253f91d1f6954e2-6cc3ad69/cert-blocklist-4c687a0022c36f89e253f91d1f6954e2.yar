import "pe"
rule cert_blocklist_4c687a0022c36f89e253f91d1f6954e2 {
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
            pe.signatures[i].subject contains "HETCO ApS" and
            pe.signatures[i].serial == "4c:68:7a:00:22:c3:6f:89:e2:53:f9:1d:1f:69:54:e2" and
            1606780800 <= pe.signatures[i].not_after
        )
}