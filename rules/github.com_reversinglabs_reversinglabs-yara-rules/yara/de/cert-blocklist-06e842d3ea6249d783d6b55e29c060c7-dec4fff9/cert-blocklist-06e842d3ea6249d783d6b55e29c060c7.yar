import "pe"
rule cert_blocklist_06e842d3ea6249d783d6b55e29c060c7 {
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
            pe.signatures[i].subject contains "PORT-SERVIS LTD, TOV" and
            pe.signatures[i].serial == "06:e8:42:d3:ea:62:49:d7:83:d6:b5:5e:29:c0:60:c7" and
            1565568000 <= pe.signatures[i].not_after
        )
}