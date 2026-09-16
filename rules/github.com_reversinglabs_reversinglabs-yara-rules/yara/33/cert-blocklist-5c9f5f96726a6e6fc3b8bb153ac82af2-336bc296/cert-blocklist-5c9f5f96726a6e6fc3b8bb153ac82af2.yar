import "pe"
rule cert_blocklist_5c9f5f96726a6e6fc3b8bb153ac82af2 {
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
            pe.signatures[i].subject contains "1105 SOFTWARE LLC" and
            pe.signatures[i].serial == "5c:9f:5f:96:72:6a:6e:6f:c3:b8:bb:15:3a:c8:2a:f2" and
            1679061408 <= pe.signatures[i].not_after
        )
}