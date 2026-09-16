import "pe"
rule cert_blocklist_0296cf3314f434c5b74d0c3e36616dd1 {
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
            pe.signatures[i].subject contains "Yu Bao" and
            pe.signatures[i].serial == "02:96:cf:33:14:f4:34:c5:b7:4d:0c:3e:36:61:6d:d1" and
            1474934400 <= pe.signatures[i].not_after
        )
}