import "pe"
rule cert_blocklist_00e8cc18cf100b6b27443ef26319398734 {
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
            pe.signatures[i].subject contains "Syngenta" and (
                pe.signatures[i].serial == "00:e8:cc:18:cf:10:0b:6b:27:44:3e:f2:63:19:39:87:34" or
                pe.signatures[i].serial == "e8:cc:18:cf:10:0b:6b:27:44:3e:f2:63:19:39:87:34"
            ) and
            1404172799 <= pe.signatures[i].not_after
        )
}