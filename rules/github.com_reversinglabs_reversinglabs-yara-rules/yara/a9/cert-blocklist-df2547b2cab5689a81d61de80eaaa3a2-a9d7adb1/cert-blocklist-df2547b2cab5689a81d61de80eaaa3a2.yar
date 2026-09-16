import "pe"
rule cert_blocklist_df2547b2cab5689a81d61de80eaaa3a2 {
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
            pe.signatures[i].subject contains "FORWARD MUSIC AGENCY SRL" and (
                pe.signatures[i].serial == "00:df:25:47:b2:ca:b5:68:9a:81:d6:1d:e8:0e:aa:a3:a2" or
                pe.signatures[i].serial == "df:25:47:b2:ca:b5:68:9a:81:d6:1d:e8:0e:aa:a3:a2"
            ) and
            1657756800 <= pe.signatures[i].not_after
        )
}