import "pe"
rule cert_blocklist_0a01a91cce63ede5eaa3dac4883aea05 {
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
            pe.signatures[i].subject contains "Seacloud Technologies Pte. Ltd." and
            pe.signatures[i].serial == "0a:01:a9:1c:ce:63:ed:e5:ea:a3:da:c4:88:3a:ea:05" and
            1618876800 <= pe.signatures[i].not_after
        )
}