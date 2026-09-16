import "pe"
rule cert_blocklist_832e161aea5206d815f973e5a1feb3e7 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing SeedLocker ransomware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Project NSRM Ltd" and (
                pe.signatures[i].serial == "00:83:2e:16:1a:ea:52:06:d8:15:f9:73:e5:a1:fe:b3:e7" or
                pe.signatures[i].serial == "83:2e:16:1a:ea:52:06:d8:15:f9:73:e5:a1:fe:b3:e7"
            ) and
            1549830060 <= pe.signatures[i].not_after
        )
}