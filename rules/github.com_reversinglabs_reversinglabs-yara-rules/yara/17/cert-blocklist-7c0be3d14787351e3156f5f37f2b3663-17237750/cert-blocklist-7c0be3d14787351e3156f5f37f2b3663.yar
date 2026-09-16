import "pe"
rule cert_blocklist_7c0be3d14787351e3156f5f37f2b3663 {
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
            pe.signatures[i].subject contains "Apex Tech, SIA" and
            pe.signatures[i].serial == "7c:0b:e3:d1:47:87:35:1e:31:56:f5:f3:7f:2b:36:63" and
            1523318400 <= pe.signatures[i].not_after
        )
}