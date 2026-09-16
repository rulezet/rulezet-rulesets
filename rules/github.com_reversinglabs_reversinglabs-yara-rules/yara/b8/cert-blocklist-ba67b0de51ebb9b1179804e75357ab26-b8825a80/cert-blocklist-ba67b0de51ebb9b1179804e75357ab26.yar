import "pe"
rule cert_blocklist_ba67b0de51ebb9b1179804e75357ab26 {
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
            pe.signatures[i].subject contains "Fjordland Bike Wear ApS" and (
                pe.signatures[i].serial == "00:ba:67:b0:de:51:eb:b9:b1:17:98:04:e7:53:57:ab:26" or
                pe.signatures[i].serial == "ba:67:b0:de:51:eb:b9:b1:17:98:04:e7:53:57:ab:26"
            ) and
            1636145940 <= pe.signatures[i].not_after
        )
}