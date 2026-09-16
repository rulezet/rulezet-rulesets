import "pe"
rule cert_blocklist_7d824ba1f7f730319c50d64c9a7ed507 {
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
            pe.signatures[i].subject contains "joaweb" and
            pe.signatures[i].serial == "7d:82:4b:a1:f7:f7:30:31:9c:50:d6:4c:9a:7e:d5:07" and
            1238025599 <= pe.signatures[i].not_after
        )
}