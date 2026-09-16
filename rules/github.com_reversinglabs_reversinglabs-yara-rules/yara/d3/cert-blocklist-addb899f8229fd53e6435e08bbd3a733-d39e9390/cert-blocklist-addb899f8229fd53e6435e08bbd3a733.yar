import "pe"
rule cert_blocklist_addb899f8229fd53e6435e08bbd3a733 {
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
            pe.signatures[i].subject contains "U.K. STEEL EXPORTS LIMITED" and (
                pe.signatures[i].serial == "00:ad:db:89:9f:82:29:fd:53:e6:43:5e:08:bb:d3:a7:33" or
                pe.signatures[i].serial == "ad:db:89:9f:82:29:fd:53:e6:43:5e:08:bb:d3:a7:33"
            ) and
            1616630400 <= pe.signatures[i].not_after
        )
}