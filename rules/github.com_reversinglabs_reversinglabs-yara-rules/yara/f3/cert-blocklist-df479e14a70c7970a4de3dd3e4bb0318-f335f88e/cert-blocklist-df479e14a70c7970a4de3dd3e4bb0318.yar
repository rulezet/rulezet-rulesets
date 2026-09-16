import "pe"
rule cert_blocklist_df479e14a70c7970a4de3dd3e4bb0318 {
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
            pe.signatures[i].subject contains "SOFTWARE HUB IT LTD" and (
                pe.signatures[i].serial == "00:df:47:9e:14:a7:0c:79:70:a4:de:3d:d3:e4:bb:03:18" or
                pe.signatures[i].serial == "df:47:9e:14:a7:0c:79:70:a4:de:3d:d3:e4:bb:03:18"
            ) and
            1591660800 <= pe.signatures[i].not_after
        )
}