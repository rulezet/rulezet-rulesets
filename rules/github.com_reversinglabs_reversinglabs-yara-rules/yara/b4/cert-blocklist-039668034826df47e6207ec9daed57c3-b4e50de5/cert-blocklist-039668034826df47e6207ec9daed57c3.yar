import "pe"
rule cert_blocklist_039668034826df47e6207ec9daed57c3 {
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
            pe.signatures[i].subject contains "CHOO FSP, LLC" and
            pe.signatures[i].serial == "03:96:68:03:48:26:df:47:e6:20:7e:c9:da:ed:57:c3" and
            1601424001 <= pe.signatures[i].not_after
        )
}