import "pe"
rule cert_blocklist_418f6d959a8a0f82bef07ceba3603e52 {
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
            pe.signatures[i].subject contains "OORT inc." and (
                pe.signatures[i].serial == "00:41:8f:6d:95:9a:8a:0f:82:be:f0:7c:eb:a3:60:3e:52" or
                pe.signatures[i].serial == "41:8f:6d:95:9a:8a:0f:82:be:f0:7c:eb:a3:60:3e:52"
            ) and
            1601928240 <= pe.signatures[i].not_after
        )
}