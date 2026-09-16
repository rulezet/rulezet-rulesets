import "pe"
rule cert_blocklist_e9756b3f38b1172ea89fdbdfdba5f979 {
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
            pe.signatures[i].subject contains "Kreamer Ltd" and (
                pe.signatures[i].serial == "00:e9:75:6b:3f:38:b1:17:2e:a8:9f:db:df:db:a5:f9:79" or
                pe.signatures[i].serial == "e9:75:6b:3f:38:b1:17:2e:a8:9f:db:df:db:a5:f9:79"
            ) and
            1492732800 <= pe.signatures[i].not_after
        )
}