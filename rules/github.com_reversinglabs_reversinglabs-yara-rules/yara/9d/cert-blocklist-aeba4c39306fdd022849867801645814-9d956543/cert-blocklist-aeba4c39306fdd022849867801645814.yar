import "pe"
rule cert_blocklist_aeba4c39306fdd022849867801645814 {
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
            pe.signatures[i].subject contains "SK AI MAS GmbH" and (
                pe.signatures[i].serial == "00:ae:ba:4c:39:30:6f:dd:02:28:49:86:78:01:64:58:14" or
                pe.signatures[i].serial == "ae:ba:4c:39:30:6f:dd:02:28:49:86:78:01:64:58:14"
            ) and
            1579478400 <= pe.signatures[i].not_after
        )
}