import "pe"
rule cert_blocklist_d22e026c5b5966f1cf6ef00a7c06682e {
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
            pe.signatures[i].subject contains "AMCERT, LLC" and (
                pe.signatures[i].serial == "00:d2:2e:02:6c:5b:59:66:f1:cf:6e:f0:0a:7c:06:68:2e" or
                pe.signatures[i].serial == "d2:2e:02:6c:5b:59:66:f1:cf:6e:f0:0a:7c:06:68:2e"
            ) and
            1636456620 <= pe.signatures[i].not_after
        )
}