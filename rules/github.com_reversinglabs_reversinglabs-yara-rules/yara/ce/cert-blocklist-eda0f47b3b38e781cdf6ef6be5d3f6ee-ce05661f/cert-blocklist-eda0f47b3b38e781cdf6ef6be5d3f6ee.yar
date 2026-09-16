import "pe"
rule cert_blocklist_eda0f47b3b38e781cdf6ef6be5d3f6ee {
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
            pe.signatures[i].subject contains "ADVANCED ACCESS SERVICES LTD" and (
                pe.signatures[i].serial == "00:ed:a0:f4:7b:3b:38:e7:81:cd:f6:ef:6b:e5:d3:f6:ee" or
                pe.signatures[i].serial == "ed:a0:f4:7b:3b:38:e7:81:cd:f6:ef:6b:e5:d3:f6:ee"
            ) and
            1650931200 <= pe.signatures[i].not_after
        )
}