import "pe"
rule cert_blocklist_ad255d4ebefa751f3782587396c08629 {
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
            pe.signatures[i].subject contains "OOO Ornitek" and (
                pe.signatures[i].serial == "00:ad:25:5d:4e:be:fa:75:1f:37:82:58:73:96:c0:86:29" or
                pe.signatures[i].serial == "ad:25:5d:4e:be:fa:75:1f:37:82:58:73:96:c0:86:29"
            ) and
            1614643200 <= pe.signatures[i].not_after
        )
}