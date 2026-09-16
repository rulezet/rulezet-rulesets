import "pe"
rule cert_blocklist_0087d60d1e2b9374eb7a735dce4bbdae56 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing GovRAT malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "AMO-K Limited Liability Company" and (
                pe.signatures[i].serial == "00:87:d6:0d:1e:2b:93:74:eb:7a:73:5d:ce:4b:bd:ae:56" or
                pe.signatures[i].serial == "87:d6:0d:1e:2b:93:74:eb:7a:73:5d:ce:4b:bd:ae:56"
            ) and
            1404172799 <= pe.signatures[i].not_after
        )
}