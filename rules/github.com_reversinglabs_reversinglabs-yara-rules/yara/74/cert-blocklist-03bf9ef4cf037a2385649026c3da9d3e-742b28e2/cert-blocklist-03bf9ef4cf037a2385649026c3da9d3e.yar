import "pe"
rule cert_blocklist_03bf9ef4cf037a2385649026c3da9d3e {
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
            pe.signatures[i].subject contains "COLLECTIVE SOFTWARE INC." and
            pe.signatures[i].serial == "03:bf:9e:f4:cf:03:7a:23:85:64:90:26:c3:da:9d:3e" and
            1595371955 <= pe.signatures[i].not_after
        )
}