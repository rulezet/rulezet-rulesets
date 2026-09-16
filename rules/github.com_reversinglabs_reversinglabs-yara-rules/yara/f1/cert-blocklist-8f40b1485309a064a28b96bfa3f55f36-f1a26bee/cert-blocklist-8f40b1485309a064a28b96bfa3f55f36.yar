import "pe"
rule cert_blocklist_8f40b1485309a064a28b96bfa3f55f36 {
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
            pe.signatures[i].subject contains "Singh Agile Content Design Limited" and (
                pe.signatures[i].serial == "00:8f:40:b1:48:53:09:a0:64:a2:8b:96:bf:a3:f5:5f:36" or
                pe.signatures[i].serial == "8f:40:b1:48:53:09:a0:64:a2:8b:96:bf:a3:f5:5f:36"
            ) and
            1542585600 <= pe.signatures[i].not_after
        )
}