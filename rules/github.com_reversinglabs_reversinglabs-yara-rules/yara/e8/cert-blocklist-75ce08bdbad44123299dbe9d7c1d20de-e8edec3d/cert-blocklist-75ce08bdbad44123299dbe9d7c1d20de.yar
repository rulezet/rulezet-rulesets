import "pe"
rule cert_blocklist_75ce08bdbad44123299dbe9d7c1d20de {
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
            pe.signatures[i].subject contains "Rose Holm International ApS" and
            pe.signatures[i].serial == "75:ce:08:bd:ba:d4:41:23:29:9d:be:9d:7c:1d:20:de" and
            1631007095 <= pe.signatures[i].not_after
        )
}