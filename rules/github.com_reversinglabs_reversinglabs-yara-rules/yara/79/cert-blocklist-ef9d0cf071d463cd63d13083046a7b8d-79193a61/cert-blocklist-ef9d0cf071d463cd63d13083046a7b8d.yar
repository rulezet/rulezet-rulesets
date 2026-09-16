import "pe"
rule cert_blocklist_ef9d0cf071d463cd63d13083046a7b8d {
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
            pe.signatures[i].subject contains "Rubin LLC" and (
                pe.signatures[i].serial == "00:ef:9d:0c:f0:71:d4:63:cd:63:d1:30:83:04:6a:7b:8d" or
                pe.signatures[i].serial == "ef:9d:0c:f0:71:d4:63:cd:63:d1:30:83:04:6a:7b:8d"
            ) and
            1605358307 <= pe.signatures[i].not_after
        )
}