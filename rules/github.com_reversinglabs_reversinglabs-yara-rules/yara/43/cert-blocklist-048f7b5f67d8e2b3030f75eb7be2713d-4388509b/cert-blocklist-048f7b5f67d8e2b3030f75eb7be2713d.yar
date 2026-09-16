import "pe"
rule cert_blocklist_048f7b5f67d8e2b3030f75eb7be2713d {
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
            pe.signatures[i].subject contains "RITEIL SERVIS, OOO" and
            pe.signatures[i].serial == "04:8f:7b:5f:67:d8:e2:b3:03:0f:75:eb:7b:e2:71:3d" and
            1591142400 <= pe.signatures[i].not_after
        )
}