import "pe"
rule cert_blocklist_3aab11dee52f1b19d056 {
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
            pe.signatures[i].subject contains "Microsoft Enforced Licensing Intermediate PCA" and
            pe.signatures[i].serial == "3a:ab:11:de:e5:2f:1b:19:d0:56"
        )
}