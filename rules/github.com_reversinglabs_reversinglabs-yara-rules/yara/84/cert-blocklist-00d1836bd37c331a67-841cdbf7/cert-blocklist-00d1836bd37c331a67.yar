import "pe"
rule cert_blocklist_00d1836bd37c331a67 {
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
            pe.signatures[i].subject contains "MINDSTORM LLC" and (
                pe.signatures[i].serial == "00:d1:83:6b:d3:7c:33:1a:67" or
                pe.signatures[i].serial == "d1:83:6b:d3:7c:33:1a:67"
            ) and
            1422835199 <= pe.signatures[i].not_after
        )
}