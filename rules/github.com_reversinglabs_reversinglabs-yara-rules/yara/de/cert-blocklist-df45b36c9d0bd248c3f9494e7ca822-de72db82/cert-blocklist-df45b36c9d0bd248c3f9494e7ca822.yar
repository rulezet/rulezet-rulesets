import "pe"
rule cert_blocklist_df45b36c9d0bd248c3f9494e7ca822 {
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
            pe.signatures[i].subject contains "MPO STORITVE d.o.o." and (
                pe.signatures[i].serial == "00:df:45:b3:6c:9d:0b:d2:48:c3:f9:49:4e:7c:a8:22" or
                pe.signatures[i].serial == "df:45:b3:6c:9d:0b:d2:48:c3:f9:49:4e:7c:a8:22"
            ) and
            1619740800 <= pe.signatures[i].not_after
        )
}