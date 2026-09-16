import "pe"
rule cert_blocklist_04422f12037bc2032521dbb6ae02ea0e {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing GovRAT malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Open Source Developer, Muhammad Lee" and
            pe.signatures[i].serial == "04:42:2f:12:03:7b:c2:03:25:21:db:b6:ae:02:ea:0e" and
            1404172799 <= pe.signatures[i].not_after
        )
}