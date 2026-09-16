import "pe"
rule cert_blocklist_60497070ff4a83bc87bdea24da5b431d {
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
            pe.signatures[i].subject contains "Xin Zhou" and
            pe.signatures[i].serial == "60:49:70:70:ff:4a:83:bc:87:bd:ea:24:da:5b:43:1d" and
            1477008000 <= pe.signatures[i].not_after
        )
}