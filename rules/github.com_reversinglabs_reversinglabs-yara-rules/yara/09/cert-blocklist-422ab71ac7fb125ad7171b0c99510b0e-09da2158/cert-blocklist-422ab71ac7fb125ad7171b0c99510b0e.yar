import "pe"
rule cert_blocklist_422ab71ac7fb125ad7171b0c99510b0e {
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
            pe.signatures[i].serial == "42:2a:b7:1a:c7:fb:12:5a:d7:17:1b:0c:99:51:0b:0e" and
            1475193600 <= pe.signatures[i].not_after
        )
}