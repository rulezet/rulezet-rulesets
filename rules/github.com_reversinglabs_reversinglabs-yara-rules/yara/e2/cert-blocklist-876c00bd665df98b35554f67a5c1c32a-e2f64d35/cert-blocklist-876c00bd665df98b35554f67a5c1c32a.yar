import "pe"
rule cert_blocklist_876c00bd665df98b35554f67a5c1c32a {
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
            pe.signatures[i].subject contains "Lossera-M, OOO" and (
                pe.signatures[i].serial == "00:87:6c:00:bd:66:5d:f9:8b:35:55:4f:67:a5:c1:c3:2a" or
                pe.signatures[i].serial == "87:6c:00:bd:66:5d:f9:8b:35:55:4f:67:a5:c1:c3:2a"
            ) and
            1493078400 <= pe.signatures[i].not_after
        )
}