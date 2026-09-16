import "pe"
rule cert_blocklist_0939c2bad859c0432e8e98a6c0162c02 {
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
            pe.signatures[i].subject contains "Activ Expeditions ApS" and
            pe.signatures[i].serial == "09:39:c2:ba:d8:59:c0:43:2e:8e:98:a6:c0:16:2c:02" and
            1615939200 <= pe.signatures[i].not_after
        )
}