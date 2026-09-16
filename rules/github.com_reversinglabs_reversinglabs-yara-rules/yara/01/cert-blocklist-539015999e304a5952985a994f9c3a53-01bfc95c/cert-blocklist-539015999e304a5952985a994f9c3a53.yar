import "pe"
rule cert_blocklist_539015999e304a5952985a994f9c3a53 {
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
            pe.signatures[i].subject contains "Service lab LLC" and
            pe.signatures[i].serial == "53:90:15:99:9e:30:4a:59:52:98:5a:99:4f:9c:3a:53" and
            1599181200 <= pe.signatures[i].not_after
        )
}