import "pe"
rule cert_blocklist_2fdadd0740572270203f8138692c4a83 {
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
            pe.signatures[i].subject contains "Open Source Developer, William Zoltan" and
            pe.signatures[i].serial == "2f:da:dd:07:40:57:22:70:20:3f:81:38:69:2c:4a:83" and
            1404172799 <= pe.signatures[i].not_after
        )
}