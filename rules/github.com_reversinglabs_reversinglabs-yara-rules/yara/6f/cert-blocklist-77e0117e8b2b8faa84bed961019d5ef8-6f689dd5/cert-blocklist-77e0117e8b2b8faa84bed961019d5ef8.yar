import "pe"
rule cert_blocklist_77e0117e8b2b8faa84bed961019d5ef8 {
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
            pe.signatures[i].subject contains "Reiner Wodey Informationssysteme" and
            pe.signatures[i].serial == "77:e0:11:7e:8b:2b:8f:aa:84:be:d9:61:01:9d:5e:f8" and
            1383695999 <= pe.signatures[i].not_after
        )
}