import "pe"
rule cert_blocklist_0fc4d9178b8df2c19e269ac6f43dd708 {
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
            pe.signatures[i].subject contains "PK Partnership, OOO" and
            pe.signatures[i].serial == "0f:c4:d9:17:8b:8d:f2:c1:9e:26:9a:c6:f4:3d:d7:08" and
            1466553600 <= pe.signatures[i].not_after
        )
}