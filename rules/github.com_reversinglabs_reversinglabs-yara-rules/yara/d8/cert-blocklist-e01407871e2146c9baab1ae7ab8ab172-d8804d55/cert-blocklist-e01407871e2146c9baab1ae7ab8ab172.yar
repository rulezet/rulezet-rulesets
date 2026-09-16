import "pe"
rule cert_blocklist_e01407871e2146c9baab1ae7ab8ab172 {
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
            pe.signatures[i].subject contains "TOV Intalev Ukraina" and (
                pe.signatures[i].serial == "00:e0:14:07:87:1e:21:46:c9:ba:ab:1a:e7:ab:8a:b1:72" or
                pe.signatures[i].serial == "e0:14:07:87:1e:21:46:c9:ba:ab:1a:e7:ab:8a:b1:72"
            ) and
            1464220800 <= pe.signatures[i].not_after
        )
}