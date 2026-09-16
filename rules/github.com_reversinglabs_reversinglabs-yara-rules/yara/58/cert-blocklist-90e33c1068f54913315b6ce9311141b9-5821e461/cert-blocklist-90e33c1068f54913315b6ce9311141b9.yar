import "pe"
rule cert_blocklist_90e33c1068f54913315b6ce9311141b9 {
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
            pe.signatures[i].subject contains "GERMES, OOO" and (
                pe.signatures[i].serial == "00:90:e3:3c:10:68:f5:49:13:31:5b:6c:e9:31:11:41:b9" or
                pe.signatures[i].serial == "90:e3:3c:10:68:f5:49:13:31:5b:6c:e9:31:11:41:b9"
            ) and
            1487635200 <= pe.signatures[i].not_after
        )
}