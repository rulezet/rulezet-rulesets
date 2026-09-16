import "pe"
rule cert_blocklist_6102b01900000000002f {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Microsoft Enforced Licensing Registration Authority CA (SHA1)" and
            pe.signatures[i].serial == "61:02:b0:19:00:00:00:00:00:2f"
        )
}