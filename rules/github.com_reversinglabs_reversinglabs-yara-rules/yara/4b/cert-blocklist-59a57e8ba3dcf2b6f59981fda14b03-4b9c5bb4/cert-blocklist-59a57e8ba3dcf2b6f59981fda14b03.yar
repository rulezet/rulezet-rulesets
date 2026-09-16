import "pe"
rule cert_blocklist_59a57e8ba3dcf2b6f59981fda14b03 {
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
            pe.signatures[i].subject contains "Medium LLC" and
            pe.signatures[i].serial == "59:a5:7e:8b:a3:dc:f2:b6:f5:99:81:fd:a1:4b:03" and
            1609113600 <= pe.signatures[i].not_after
        )
}