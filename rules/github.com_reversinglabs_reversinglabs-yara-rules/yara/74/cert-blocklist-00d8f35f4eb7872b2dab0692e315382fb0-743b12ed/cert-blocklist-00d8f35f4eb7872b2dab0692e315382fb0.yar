import "pe"
rule cert_blocklist_00d8f35f4eb7872b2dab0692e315382fb0 {
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
            pe.signatures[i].subject contains "global trustee" and (
                pe.signatures[i].serial == "00:d8:f3:5f:4e:b7:87:2b:2d:ab:06:92:e3:15:38:2f:b0" or
                pe.signatures[i].serial == "d8:f3:5f:4e:b7:87:2b:2d:ab:06:92:e3:15:38:2f:b0"
            ) and
            1300060800 <= pe.signatures[i].not_after
        )
}