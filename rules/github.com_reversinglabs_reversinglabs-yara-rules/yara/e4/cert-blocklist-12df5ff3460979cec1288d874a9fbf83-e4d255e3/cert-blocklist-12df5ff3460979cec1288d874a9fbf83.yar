import "pe"
rule cert_blocklist_12df5ff3460979cec1288d874a9fbf83 {
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
            pe.signatures[i].subject contains "FORWARD MUSIC AGENCY SRL" and
            pe.signatures[i].serial == "12:df:5f:f3:46:09:79:ce:c1:28:8d:87:4a:9f:bf:83" and
            1599091200 <= pe.signatures[i].not_after
        )
}