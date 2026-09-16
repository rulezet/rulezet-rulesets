import "pe"
rule cert_blocklist_642ad8e5ef8b3ac767f0d5c1a999bdaa {
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
            pe.signatures[i].subject contains "Itgms Ltd" and
            pe.signatures[i].serial == "64:2a:d8:e5:ef:8b:3a:c7:67:f0:d5:c1:a9:99:bd:aa" and
            1447804800 <= pe.signatures[i].not_after
        )
}