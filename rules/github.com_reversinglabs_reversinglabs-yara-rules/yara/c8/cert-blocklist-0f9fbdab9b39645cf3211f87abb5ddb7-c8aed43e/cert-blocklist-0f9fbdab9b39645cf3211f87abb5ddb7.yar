import "pe"
rule cert_blocklist_0f9fbdab9b39645cf3211f87abb5ddb7 {
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
            pe.signatures[i].subject contains "The Motivo Group, Inc." and
            pe.signatures[i].serial == "0f:9f:bd:ab:9b:39:64:5c:f3:21:1f:87:ab:b5:dd:b7" and
            1361318399 <= pe.signatures[i].not_after
        )
}