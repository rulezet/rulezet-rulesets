import "pe"
rule cert_blocklist_c51f4cf4d82bc920421e1ad93e39d490 {
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
            pe.signatures[i].subject contains "CUT AHEAD LTD" and (
                pe.signatures[i].serial == "00:c5:1f:4c:f4:d8:2b:c9:20:42:1e:1a:d9:3e:39:d4:90" or
                pe.signatures[i].serial == "c5:1f:4c:f4:d8:2b:c9:20:42:1e:1a:d9:3e:39:d4:90"
            ) and
            1644624000 <= pe.signatures[i].not_after
        )
}