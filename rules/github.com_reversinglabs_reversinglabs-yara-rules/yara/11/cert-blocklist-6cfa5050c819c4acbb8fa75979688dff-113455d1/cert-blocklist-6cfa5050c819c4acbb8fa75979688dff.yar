import "pe"
rule cert_blocklist_6cfa5050c819c4acbb8fa75979688dff {
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
            pe.signatures[i].subject contains "Elite Web Development Ltd." and (
                pe.signatures[i].serial == "00:6c:fa:50:50:c8:19:c4:ac:bb:8f:a7:59:79:68:8d:ff" or
                pe.signatures[i].serial == "6c:fa:50:50:c8:19:c4:ac:bb:8f:a7:59:79:68:8d:ff"
            ) and
            1600176940 <= pe.signatures[i].not_after
        )
}