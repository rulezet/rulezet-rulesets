import "pe"
rule cert_blocklist_be89936c26cd0d845074f6b7b47f480c {
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
            pe.signatures[i].subject contains "Argus Security Maintenance Systems Inc." and (
                pe.signatures[i].serial == "00:be:89:93:6c:26:cd:0d:84:50:74:f6:b7:b4:7f:48:0c" or
                pe.signatures[i].serial == "be:89:93:6c:26:cd:0d:84:50:74:f6:b7:b4:7f:48:0c"
            ) and
            1634235015 <= pe.signatures[i].not_after
        )
}