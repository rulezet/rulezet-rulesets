import "pe"
rule cert_blocklist_f2d693aad63e6920782a0027dfc97d91 {
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
            pe.signatures[i].subject contains "EKO-KHIM TOV" and (
                pe.signatures[i].serial == "00:f2:d6:93:aa:d6:3e:69:20:78:2a:00:27:df:c9:7d:91" or
                pe.signatures[i].serial == "f2:d6:93:aa:d6:3e:69:20:78:2a:00:27:df:c9:7d:91"
            ) and
            1598989763 <= pe.signatures[i].not_after
        )
}