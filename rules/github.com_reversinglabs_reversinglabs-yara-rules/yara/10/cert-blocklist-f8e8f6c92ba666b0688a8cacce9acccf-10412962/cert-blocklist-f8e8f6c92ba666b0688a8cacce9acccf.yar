import "pe"
rule cert_blocklist_f8e8f6c92ba666b0688a8cacce9acccf {
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
            pe.signatures[i].subject contains "5 th Dimension LTD Oy" and (
                pe.signatures[i].serial == "00:f8:e8:f6:c9:2b:a6:66:b0:68:8a:8c:ac:ce:9a:cc:cf" or
                pe.signatures[i].serial == "f8:e8:f6:c9:2b:a6:66:b0:68:8a:8c:ac:ce:9a:cc:cf"
            ) and
            1618531200 <= pe.signatures[i].not_after
        )
}