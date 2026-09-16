import "pe"
rule cert_blocklist_c167f04b338b1e8747b92c2197403c43 {
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
            pe.signatures[i].subject contains "FORTUNE STAR TRADING, INC." and (
                pe.signatures[i].serial == "00:c1:67:f0:4b:33:8b:1e:87:47:b9:2c:21:97:40:3c:43" or
                pe.signatures[i].serial == "c1:67:f0:4b:33:8b:1e:87:47:b9:2c:21:97:40:3c:43"
            ) and
            1604361600 <= pe.signatures[i].not_after
        )
}