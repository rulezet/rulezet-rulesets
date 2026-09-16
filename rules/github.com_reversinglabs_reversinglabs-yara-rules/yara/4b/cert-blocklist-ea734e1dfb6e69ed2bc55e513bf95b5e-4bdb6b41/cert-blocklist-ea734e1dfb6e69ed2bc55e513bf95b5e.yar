import "pe"
rule cert_blocklist_ea734e1dfb6e69ed2bc55e513bf95b5e {
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
            pe.signatures[i].subject contains "Postmarket LLC" and (
                pe.signatures[i].serial == "00:ea:73:4e:1d:fb:6e:69:ed:2b:c5:5e:51:3b:f9:5b:5e" or
                pe.signatures[i].serial == "ea:73:4e:1d:fb:6e:69:ed:2b:c5:5e:51:3b:f9:5b:5e"
            ) and
            1635153791 <= pe.signatures[i].not_after
        )
}