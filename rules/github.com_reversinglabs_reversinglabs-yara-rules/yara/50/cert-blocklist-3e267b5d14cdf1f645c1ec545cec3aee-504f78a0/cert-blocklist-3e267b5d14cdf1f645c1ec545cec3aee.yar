import "pe"
rule cert_blocklist_3e267b5d14cdf1f645c1ec545cec3aee {
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
            pe.signatures[i].subject contains "OOO KBI" and
            pe.signatures[i].serial == "3e:26:7b:5d:14:cd:f1:f6:45:c1:ec:54:5c:ec:3a:ee" and
            1579825892 <= pe.signatures[i].not_after
        )
}