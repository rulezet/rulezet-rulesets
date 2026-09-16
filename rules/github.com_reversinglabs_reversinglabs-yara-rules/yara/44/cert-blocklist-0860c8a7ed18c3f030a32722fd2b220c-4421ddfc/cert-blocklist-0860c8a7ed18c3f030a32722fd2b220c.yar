import "pe"
rule cert_blocklist_0860c8a7ed18c3f030a32722fd2b220c {
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
            pe.signatures[i].subject contains "Open Source Developer, Tony Yeh" and
            pe.signatures[i].serial == "08:60:c8:a7:ed:18:c3:f0:30:a3:27:22:fd:2b:22:0c" and
            1404172799 <= pe.signatures[i].not_after
        )
}