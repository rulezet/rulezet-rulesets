import "pe"
rule cert_blocklist_0bc9b800f480691bd6b60963466b0c75 {
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
            pe.signatures[i].subject contains "HasCred ApS" and
            pe.signatures[i].serial == "0b:c9:b8:00:f4:80:69:1b:d6:b6:09:63:46:6b:0c:75" and
            1629158400 <= pe.signatures[i].not_after
        )
}