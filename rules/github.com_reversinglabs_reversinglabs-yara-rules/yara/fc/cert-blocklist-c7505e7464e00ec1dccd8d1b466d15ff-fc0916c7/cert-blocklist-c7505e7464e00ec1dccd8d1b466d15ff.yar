import "pe"
rule cert_blocklist_c7505e7464e00ec1dccd8d1b466d15ff {
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
            pe.signatures[i].subject contains "Ltd. \"Eve Beauty\"" and (
                pe.signatures[i].serial == "00:c7:50:5e:74:64:e0:0e:c1:dc:cd:8d:1b:46:6d:15:ff" or
                pe.signatures[i].serial == "c7:50:5e:74:64:e0:0e:c1:dc:cd:8d:1b:46:6d:15:ff"
            ) and
            1583824676 <= pe.signatures[i].not_after
        )
}