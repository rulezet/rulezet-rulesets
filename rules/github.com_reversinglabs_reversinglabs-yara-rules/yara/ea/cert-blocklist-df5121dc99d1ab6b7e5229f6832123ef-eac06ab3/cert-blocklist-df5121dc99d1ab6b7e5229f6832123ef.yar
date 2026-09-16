import "pe"
rule cert_blocklist_df5121dc99d1ab6b7e5229f6832123ef {
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
            pe.signatures[i].subject contains "INC SALYUT" and (
                pe.signatures[i].serial == "00:df:51:21:dc:99:d1:ab:6b:7e:52:29:f6:83:21:23:ef" or
                pe.signatures[i].serial == "df:51:21:dc:99:d1:ab:6b:7e:52:29:f6:83:21:23:ef"
            ) and
            1613433600 <= pe.signatures[i].not_after
        )
}