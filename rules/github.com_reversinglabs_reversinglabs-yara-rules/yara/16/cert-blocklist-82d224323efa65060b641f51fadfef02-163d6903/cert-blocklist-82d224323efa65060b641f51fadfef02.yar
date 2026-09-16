import "pe"
rule cert_blocklist_82d224323efa65060b641f51fadfef02 {
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
            pe.signatures[i].subject contains "SAVAS INVESTMENTS PTY LTD" and (
                pe.signatures[i].serial == "00:82:d2:24:32:3e:fa:65:06:0b:64:1f:51:fa:df:ef:02" or
                pe.signatures[i].serial == "82:d2:24:32:3e:fa:65:06:0b:64:1f:51:fa:df:ef:02"
            ) and
            1665100800 <= pe.signatures[i].not_after
        )
}