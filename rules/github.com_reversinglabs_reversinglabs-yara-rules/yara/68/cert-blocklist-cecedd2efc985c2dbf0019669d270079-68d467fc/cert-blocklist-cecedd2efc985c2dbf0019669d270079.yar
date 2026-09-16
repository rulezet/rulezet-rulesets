import "pe"
rule cert_blocklist_cecedd2efc985c2dbf0019669d270079 {
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
            pe.signatures[i].subject contains "TRANS LTD" and (
                pe.signatures[i].serial == "00:ce:ce:dd:2e:fc:98:5c:2d:bf:00:19:66:9d:27:00:79" or
                pe.signatures[i].serial == "ce:ce:dd:2e:fc:98:5c:2d:bf:00:19:66:9d:27:00:79"
            ) and
            1527811200 <= pe.signatures[i].not_after
        )
}