import "pe"
rule cert_blocklist_4b093cb60d4b992266f550934a4ac7d0 {
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
            pe.signatures[i].subject contains "LCB SISTEMAS LTDA ME" and
            pe.signatures[i].serial == "4b:09:3c:b6:0d:4b:99:22:66:f5:50:93:4a:4a:c7:d0" and
            1478649600 <= pe.signatures[i].not_after
        )
}