import "pe"
rule cert_blocklist_1a35acce5b0c77206b1c3dc2a6a2417c {
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
            pe.signatures[i].subject contains "cd ingegneri associati srl" and
            pe.signatures[i].serial == "1a:35:ac:ce:5b:0c:77:20:6b:1c:3d:c2:a6:a2:41:7c" and
            1166054399 <= pe.signatures[i].not_after
        )
}