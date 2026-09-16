import "pe"
rule cert_blocklist_a32b8b4f1be43c23eb2848ab4ef06bb2 {
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
            pe.signatures[i].subject contains "Pak El AB" and (
                pe.signatures[i].serial == "00:a3:2b:8b:4f:1b:e4:3c:23:eb:28:48:ab:4e:f0:6b:b2" or
                pe.signatures[i].serial == "a3:2b:8b:4f:1b:e4:3c:23:eb:28:48:ab:4e:f0:6b:b2"
            ) and
            1673395200 <= pe.signatures[i].not_after
        )
}