import "pe"
rule cert_blocklist_02eaf27e6f1575e365fc7fe4e0be43f7 {
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
            pe.signatures[i].subject contains "Theravada Solutions Ltd" and
            pe.signatures[i].serial == "02:ea:f2:7e:6f:15:75:e3:65:fc:7f:e4:e0:be:43:f7" and
            1562889600 <= pe.signatures[i].not_after
        )
}