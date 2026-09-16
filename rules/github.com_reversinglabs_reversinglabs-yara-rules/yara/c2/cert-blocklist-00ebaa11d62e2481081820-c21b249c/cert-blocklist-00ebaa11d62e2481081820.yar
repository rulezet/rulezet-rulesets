import "pe"
rule cert_blocklist_00ebaa11d62e2481081820 {
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
            pe.signatures[i].subject contains "Microsoft Enforced Licensing Intermediate PCA" and (
                pe.signatures[i].serial == "00:eb:aa:11:d6:2e:24:81:08:18:20" or
                pe.signatures[i].serial == "eb:aa:11:d6:2e:24:81:08:18:20"
            )
        )
}