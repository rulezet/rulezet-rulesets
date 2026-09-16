import "pe"
rule cert_blocklist_6e0ccbdfb4777e10ea6221b90dc350c2 {
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
            pe.signatures[i].subject contains "TRAUMALAB INTERNATIONAL APS" and
            pe.signatures[i].serial == "6e:0c:cb:df:b4:77:7e:10:ea:62:21:b9:0d:c3:50:c2" and
            1603046620 <= pe.signatures[i].not_after
        )
}