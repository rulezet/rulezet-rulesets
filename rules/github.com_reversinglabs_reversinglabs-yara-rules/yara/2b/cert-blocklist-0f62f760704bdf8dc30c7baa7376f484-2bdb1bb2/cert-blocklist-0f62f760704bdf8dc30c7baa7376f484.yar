import "pe"
rule cert_blocklist_0f62f760704bdf8dc30c7baa7376f484 {
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
            pe.signatures[i].subject contains "Shanghai XuSong investment partnership Enterprise(Limited)" and
            pe.signatures[i].serial == "0f:62:f7:60:70:4b:df:8d:c3:0c:7b:aa:73:76:f4:84" and
            1659398400 <= pe.signatures[i].not_after
        )
}